//! Inode-relevant operations

use array_macro::array;

use core::{cmp::min, mem, panic, ptr};

use crate::mm::Address;
use crate::spinlock::SpinLock;
use crate::sleeplock::{SleepLock, SleepLockGuard};
use crate::process::CPU_MANAGER;
use crate::consts::fs::{NINODE, BSIZE, NDIRECT, NINDIRECT, MAX_DIR_SIZE, MAX_FILE_SIZE, ROOTDEV, ROOTINUM};
use super::{BCACHE, BufData, superblock::SUPER_BLOCK, LOG};
use super::block::{bm_alloc, bm_free, inode_alloc};

/// 全局唯一的 inode 缓存（inode cache），用于管理内存中活跃的 inode 实例。
///
/// # 功能说明
/// `ICACHE` 提供了整个内核中 inode 的集中缓存和引用计数机制，避免频繁从磁盘加载 inode，
/// 同时实现 inode 生命周期和同步管理。所有通过路径访问、文件打开、
/// 创建等行为所涉及的 inode 均从该缓存中获取或维护。
///
/// # 实现说明
/// - `ICACHE` 是一个静态全局变量，生命周期与内核一致；
/// - 内部维护两个数组：
///   - `meta`: 每个 inode 的元信息（如 dev、inum、引用计数），通过 `SpinLock` 保护；
///   - `data`: 实际的 inode 内容（如类型、大小、数据块地址等），通过 `SleepLock` 保护；
/// - 通过 `get()` / `dup()` / `put()` 控制 inode 的获取、克隆与释放，
///   结合引用计数和 Drop 实现自动管理。
pub static ICACHE: InodeCache = InodeCache::new();

/// 内核中的 inode 缓存池，维护所有活跃 inode 的元数据与内容数据。
///
/// # 结构体用途
/// `InodeCache`负责统一管理所有正在使用或被引用的 inode 实例，避免重复从磁盘读取，
/// 并提供线程安全的 inode 生命周期控制机制。
///
/// - 结构体中的两个数组分别维护元数据和实际数据：
///   - `meta` 包含设备号、inode号、引用计数等，用于判重与生命周期管理；
///   - `data` 包含实际 `DiskInode` 内容和有效性信息，支持按需从磁盘加载和更新；
///
/// 所有 inode 操作（如打开文件、路径解析、目录遍历等）都基于该缓存执行，
/// 并结合引用计数与 Drop 自动释放 inode 占用的资源。
pub struct InodeCache {
    /// Inode 元信息数组，包含设备号、inode 编号和引用计数等。
    /// 受全局自旋锁保护，确保并发安全地分配、查找、释放 inode。
    meta: SpinLock<[InodeMeta; NINODE]>,

    /// Inode 实际内容数组，对应每个 inode 的具体数据与状态。
    /// 每个元素通过独立的睡眠锁（SleepLock）保护，支持阻塞式互斥访问。
    data: [SleepLock<InodeData>; NINODE],
}


impl InodeCache {
    const fn new() -> Self {
        Self {
            meta: SpinLock::new(array![_ => InodeMeta::new(); NINODE], "InodeMeta"),
            data: array![_ => SleepLock::new(InodeData::new(), "InodeData"); NINODE],
        }
    }

    /// 在 inode 缓存中查找指定编号的 inode。
    ///
    /// # 功能说明
    /// 给定设备号 `dev` 和 inode 编号 `inum`，在缓存中查找是否已有对应的 inode 实例。
    /// 若存在则返回对应 handle，并增加其引用计数；
    /// 若不存在，则在缓存中分配一个空闲位置保存该 inode 的元信息（但不会立即从磁盘加载数据），返回新的 handle。
    ///
    /// # 流程解释
    /// 1. 加锁 `meta` 自旋锁，保护对 inode 元信息数组的访问；
    /// 2. 遍历缓存，查找是否已存在匹配的 `(dev, inum)` 且引用计数大于 0 的条目；
    /// 3. 如果找到，则增加引用计数并返回；
    /// 4. 如果未找到，记录第一个空闲项位置；
    /// 5. 若没有空闲项，则触发 panic；
    /// 6. 否则填入新项的元信息并初始化引用计数为 1，构造并返回新的 `Inode`。
    ///
    /// # 参数
    /// - `dev`: 设备号，标识 inode 所属设备；
    /// - `inum`: inode 编号，唯一标识该 inode 在设备上的位置；
    ///
    /// # 返回值
    /// 返回一个 [`Inode`] 句柄，包含 `(dev, inum)` 和在缓存数组中的索引。
    ///
    /// # 可能的错误
    /// - 若缓存已满（即没有可用的空闲项），将触发 panic：
    ///   `"inode: not enough"`，表示系统支持的同时活动 inode 数量不足；
    ///
    /// # 安全性
    /// - 该函数只访问 inode 的元信息数组 `meta`，不涉及 inode 数据内容；
    /// - 不会访问裸指针或执行任何 `unsafe` 操作；
    /// - 缓存分配策略依赖引用计数逻辑，错误使用可能导致缓存项泄漏或提前回收；
    fn get(&self, dev: u32, inum: u32) -> Inode {
        let mut guard = self.meta.lock();
        
        // lookup in the cache
        let mut empty_i: Option<usize> = None;
        for i in 0..NINODE {
            if guard[i].inum == inum && guard[i].refs > 0 && guard[i].dev == dev {
                guard[i].refs += 1;
                return Inode { 
                    dev,
                    inum,
                    index: i,
                }
            }
            if empty_i.is_none() && guard[i].refs == 0 {
                empty_i = Some(i);
            }
        }

        // not found
        let empty_i = match empty_i {
            Some(i) => i,
            None => panic!("inode: not enough"),
        };
        guard[empty_i].dev = dev;
        guard[empty_i].inum = inum;
        guard[empty_i].refs = 1;
        Inode {
            dev,
            inum,
            index: empty_i
        }
    }

    /// 克隆一个 inode 句柄，仅通过增加引用计数来实现共享。
    ///
    /// # 功能说明
    /// 该函数用于在 inode 缓存中对已有的 inode 进行浅拷贝（clone），
    /// 实质上通过增加其引用计数来实现多个句柄共享同一个 inode 缓存项。
    /// 常用于目录遍历、文件描述符复制等需要共享 inode 的场景。
    ///
    /// # 流程解释
    /// 1. 加锁 `meta` 数组的自旋锁以安全访问 inode 元信息；
    /// 2. 根据传入 inode 的索引值，直接将对应 inode 的引用计数加一；
    /// 3. 返回一个新的 [`Inode`] 实例，字段与原始 inode 相同。
    ///
    /// # 参数
    /// - `inode`: 原始的 inode 句柄，指向缓存中的某个有效项。
    ///
    /// # 返回值
    /// 返回一个新的 [`Inode`]，与输入句柄共享底层缓存条目。
    ///
    /// # 可能的错误
    /// - 本函数本身不会返回错误；
    /// - 但若传入的 inode 索引无效（例如在引用已被回收后调用），则可能导致数据竞争或逻辑错误（由调用者负责避免）。
    ///
    /// # 安全性
    /// - 本函数不会访问 inode 的实际数据内容；
    /// - 只在持有自旋锁的情况下安全修改引用计数，不涉及裸指针；
    /// - 需要确保传入的 `inode.index` 合法，并且未在并发上下文中被 Drop 掉；
    fn dup(&self, inode: &Inode) -> Inode {
        let mut guard = self.meta.lock();
        guard[inode.index].refs += 1;
        Inode {
            dev: inode.dev,
            inum: inode.inum,
            index: inode.index,
        }
    }

    /// 释放对一个 inode 的引用，并在合适时清理或回收该 inode。
    ///
    /// # 功能说明
    /// 本函数用于减少 inode 的引用计数。当引用计数降至 0 且该 inode 不再被任何目录链接（即 nlink 为 0）引用时，
    /// 它会被标记为空类型并清除其磁盘块，从而实现 inode 的回收与复用。
    /// 通常由 [`Inode`] 的 `Drop` 实现自动调用，用户无需手动调用。
    ///
    /// # 流程解释
    /// 1. 加锁 `meta` 数组，获取该 inode 对应的元信息；
    /// 2. 若引用计数为 1，表示这是最后一个引用：
    ///     - 获取并锁定对应的数据项；
    ///     - 若该 inode 内容未加载或还有硬链接，则仅清除缓存有效性；
    ///     - 否则说明可以安全删除 inode 数据：
    ///         - 将其类型设为 `Empty`；
    ///         - 清空数据块（调用 `truncate`）；
    ///         - 清除缓存有效性；
    ///         - 最后重新加锁 `meta`，将引用计数降为 0；
    /// 3. 若引用计数大于 1，仅减少计数；
    /// 4. 最终释放所有锁。
    ///
    /// # 参数
    /// - `inode`: 需释放引用的 inode 句柄（通常来自被 `Drop` 的 [`Inode`] 实例）；
    ///
    /// # 返回值
    /// 无返回值；
    ///
    /// # 可能的错误
    /// - 若调用时引用计数已为 0 或 index 无效，将导致内存逻辑错误（调用者需确保语义正确）；
    /// - 若误将 inode 在仍被引用或未同步的状态下回收，可能导致数据不一致；
    ///
    /// # 安全性
    /// - 函数使用多重锁机制（`SpinLock` + `SleepLock`）确保并发访问下的正确性；
    /// - 需特别注意只有在 inode 数据已完成写回磁盘后才能释放其缓存内容（见注释警告）；
    /// - 所有裸指针访问封装在受保护的结构中，当前函数不涉及 unsafe 操作；
    fn put(&self, inode: &mut Inode) {
        let mut guard = self.meta.lock();
        let i = inode.index;
        let imeta = &mut guard[i];

        if imeta.refs == 1 {
            // SAFETY: reference count is 1, so this lock will not block.
            let mut idata = self.data[i].lock();
            if idata.valid.is_none() || idata.dinode.nlink > 0 {
                idata.valid.take();
                drop(idata);
                imeta.refs -= 1;
                drop(guard);
            } else {
                drop(guard);
                idata.dinode.itype = InodeType::Empty;
                idata.truncate();
                idata.valid.take();
                drop(idata);

                // recycle after this inode content in the cache is no longer valid.
                // note: it is wrong to recycle it earlier,
                // otherwise the cache content might change
                // before the previous content written to disk.
                let mut guard = self.meta.lock();
                guard[i].refs -= 1;
                debug_assert_eq!(guard[i].refs, 0);
                drop(guard);
            }
        } else {
            imeta.refs -= 1;
            drop(guard);
        }
    }

    /// 路径解析的辅助函数，为 `namei` 和 `namei_parent` 提供通用的路径遍历逻辑。
    ///
    /// # 功能说明
    /// 根据传入的路径字符串递归查找对应的 inode。支持两种模式：
    /// - 若 `is_parent == false`，则返回路径末尾对应的 inode；
    /// - 若 `is_parent == true`，则返回路径中倒数第二级目录的 inode，并将最后一级名称写入 `name` 中。
    ///
    /// 该函数封装了 Unix 风格路径解析的过程，包括根目录/当前工作目录判断、
    /// 多级目录递归遍历、目录合法性检查等，是路径到 inode 映射的核心实现。
    ///
    /// # 流程解释
    /// 1. 根据路径首字符判断起始点是根目录还是当前进程的工作目录；
    /// 2. 利用 `skip_path` 解析每一级路径名并写入 `name`；
    /// 3. 每步使用 inode 的 `lock` 获取数据，确保类型为目录；
    /// 4. 若正在查找父目录且到达路径末尾，则返回当前目录；
    /// 5. 否则继续向下一级目录查找，直到路径解析完成；
    /// 6. 若中间存在非法路径（非目录或目录项不存在），则返回 `None`。
    ///
    /// # 参数
    /// - `path`: 以 0 字节结尾的字节串形式路径（如 `b"/a/b/c\0"`）；
    /// - `name`: 用于保存最后一级路径名或当前路径片段（必须为 `MAX_DIR_SIZE` 长度）；
    /// - `is_parent`: 若为 `true`，则返回父目录 inode 并将子项名称写入 `name`；否则返回完整路径末尾的 inode；
    ///
    /// # 返回值
    /// - 成功时返回 [`Some(inode)`]；
    /// - 若路径非法、目录项缺失或类型错误，返回 [`None`]。
    ///
    /// # 可能的错误
    /// - 路径指向非目录 inode 时中止返回 `None`；
    /// - 路径中某级目录项不存在时返回 `None`；
    /// - 若查找父目录但路径为根目录，则无法返回其父，打印警告并返回 `None`；
    ///
    /// # 安全性
    /// - 读取当前工作目录使用 `unsafe { CPU_MANAGER.my_proc() }`，调用者需确保当前进程存在；
    /// - 整个遍历过程持有 inode 的 `SleepLock` 保护目录项读取；
    /// - 返回的 inode 持有引用计数，需通过 Drop 自动管理其释放；
    fn namex(&self, path: &[u8], name: &mut [u8; MAX_DIR_SIZE], is_parent: bool) -> Option<Inode> {
        let mut inode: Inode;
        if path[0] == b'/' {
            inode = self.get(ROOTDEV, ROOTINUM);
        } else {
            let p = unsafe { CPU_MANAGER.my_proc() };
            inode = self.dup(p.data.get_mut().cwd.as_ref().unwrap());
        }

        let mut cur: usize = 0;
        loop {
            cur = skip_path(path, cur, name);
            if cur == 0 {
                break;
            }
            let mut data_guard = inode.lock();
            if data_guard.dinode.itype != InodeType::Directory {
                drop(data_guard);
                return None
            }
            if is_parent && path[cur] == 0 {
                drop(data_guard);
                return Some(inode)
            }
            match data_guard.dir_lookup(name, false) {
                None => {
                    drop(data_guard);
                    return None
                },
                Some((last_inode, _)) => {
                    drop(data_guard);
                    inode = last_inode;
                },
            }
        }

        if is_parent {
            // only when querying root inode's parent
            println!("kernel warning: namex querying root inode's parent");
            None
        } else {
            Some(inode)
        }
    }

    /// 解析给定路径并返回其对应的 inode。
    ///
    /// # 功能说明
    /// `namei` 实现了将 Unix 风格路径名解析为内核中对应的 [`Inode`] 的功能，
    /// 是文件系统中用于打开、读取、创建文件的基础入口。其支持从根目录或当前工作目录出发，
    /// 按照路径层级查找目录项，最终返回路径末尾对应的 inode。
    ///
    /// # 流程解释
    /// 1. 创建一个用于暂存路径片段的 `name` 缓冲区；
    /// 2. 调用私有方法 `namex()` 进行实际的路径递归解析，`is_parent` 参数为 `false` 表示查找完整路径目标；
    /// 3. 若路径解析成功，返回对应 inode；否则返回 `None`。
    ///
    /// # 参数
    /// - `path`: 表示文件路径的字节切片（如 `b"/usr/bin/test\0"`），必须以 `0u8` 结尾以避免越界；
    ///
    /// # 返回值
    /// - 返回 [`Some(Inode)`] 表示路径解析成功并找到目标文件；
    /// - 返回 [`None`] 表示路径非法、某级目录项缺失或类型错误。
    ///
    /// # 可能的错误
    /// - 若路径中某一级不存在或为非目录，将导致解析失败返回 `None`；
    /// - 若 `path` 不以 `0u8` 结尾，`skip_path` 等函数可能出现越界访问，从而引发 panic；
    /// - 如果未在事务 (`LOG.begin_op()`/`end_op()`) 中调用此函数，则后续对 inode 的释放操作可能破坏一致性；
    ///
    /// # 安全性
    /// - 该函数本身未使用 `unsafe` 代码；
    /// - 使用内部锁机制保护 inode 缓存读取；
    /// - 路径解析依赖于安全的切片访问和内部引用计数机制，调用方需确保路径以空字节结尾以避免边界错误；
    pub fn namei(&self, path: &[u8]) -> Option<Inode> {
        let mut name: [u8; MAX_DIR_SIZE] = [0; MAX_DIR_SIZE];
        self.namex(path, &mut name, false)
    }

    /// Same behavior as `namei`, but return the parent of the inode,
    /// and copy the end path into name.
    pub fn namei_parent(&self, path: &[u8], name: &mut [u8; MAX_DIR_SIZE]) -> Option<Inode> {
        self.namex(path, name, true)
    }

    /// 在给定路径上查找并创建一个新的 inode。
    ///
    /// # 功能说明
    /// 该函数实现路径所对应文件或目录的创建逻辑。若路径对应的 inode 已存在，
    /// 则根据 `reuse` 参数决定是否返回已有 inode 或直接失败；
    /// 若不存在，则在其父目录中创建一个新的 inode，并在必要时初始化其目录结构（如 `.` 和 `..`）。
    ///
    /// # 流程解释
    /// 1. 通过 `namei_parent` 解析路径，获取父目录的 inode 以及路径末尾的名称 `name`；
    /// 2. 在父目录中查找是否已存在该名称的目录项：
    ///     - 若存在且 `reuse == true`，则返回该 inode；
    ///     - 若存在且 `reuse == false`，则返回 `None`；
    /// 3. 若不存在，调用 `inode_alloc` 在磁盘中分配新的 inode 编号；
    /// 4. 通过 `get` 获取该 inode 对应的缓存，并填入设备号、主/次设备号、nlink 等字段；
    /// 5. 若新建的是目录类型 inode，需初始化 `.` 和 `..` 链接，并更新父目录 nlink；
    /// 6. 最后将新建的 inode 链接到父目录中，并返回对应的 [`Inode`] 实例。
    ///
    /// # 参数
    /// - `path`: 要创建的文件或目录的完整路径（以空字节结尾）；
    /// - `itype`: 要创建的 inode 类型（文件、目录或设备）；
    /// - `major`: 主设备号（仅对设备 inode 有意义）；
    /// - `minor`: 次设备号（仅对设备 inode 有意义）；
    /// - `reuse`: 是否允许复用已有的 inode。如果为 `true` 且目标路径存在，则返回该 inode 而非报错；
    ///
    /// # 返回值
    /// - 成功时返回 `Some(Inode)`，表示新建或复用的 inode；
    /// - 失败时返回 `None`，可能是路径非法或目标存在但禁止复用；
    ///
    /// # 可能的错误
    /// - 若路径无法解析（如中间目录不存在或非法），将返回 `None`；
    /// - 若在目录初始化过程中（创建 `.` 和 `..`）或父目录链接失败，将触发 panic；
    /// - 若 `inode_alloc` 返回失败（磁盘 inode 已满），将导致 panic（未显式处理）；
    ///
    /// # 安全性
    /// - 使用了对当前进程 `cwd` 的 unsafe 引用，但在路径解析中已有安全校验；
    /// - 所有 inode 操作受 `SleepLock` 保护，确保并发安全；
    /// - 目录项链接写入时，日志系统应已开启（需外部保证处于 `begin_op` 事务中）以避免一致性问题；
    pub fn create(&self, path: &[u8], itype: InodeType, major: u16, minor: u16, reuse: bool) -> Option<Inode> {
        let mut name: [u8; MAX_DIR_SIZE] = [0; MAX_DIR_SIZE];
        let dir_inode = self.namei_parent(path, &mut name)?;
        let mut dir_idata = dir_inode.lock();

        // lookup first
        if let Some((inode, _)) = dir_idata.dir_lookup(&name, false) {
            if reuse {
                return Some(inode)
            } else {
                return None
            }
        }

        // not found, create it
        let (dev, _) = *dir_idata.valid.as_ref().unwrap();
        let inum = inode_alloc(dev, itype);
        let inode = self.get(dev, inum);
        let mut idata = inode.lock();
        idata.dinode.major = major;
        idata.dinode.minor = minor;
        idata.dinode.nlink = 1;
        idata.update();
        debug_assert_eq!(idata.dinode.itype, itype);

        // if dir, create . and ..
        if itype == InodeType::Directory {
            dir_idata.dinode.nlink += 1;
            dir_idata.update();
            let mut name: [u8; MAX_DIR_SIZE] = [0; MAX_DIR_SIZE];
            // . -> itself
            name[0] = b'.';
            if idata.dir_link(&name, inum).is_err() {
                panic!("dir link .");
            }
            // .. -> parent
            name[1] = b'.';
            if idata.dir_link(&name, dir_inode.inum).is_err() {
                panic!("dir link ..");
            }
        }

        if dir_idata.dir_link(&name, inum).is_err() {
            panic!("parent dir link");
        }

        drop(dir_idata);
        drop(dir_inode);
        drop(idata);
        Some(inode)
    }
}

/// 跳过路径中的一个路径分量，并将其拷贝到 `name` 缓冲区中。
///
/// # 功能说明
/// `skip_path` 用于从给定路径 `path` 的当前位置 `cur` 开始，跳过前导 `'/'`，
/// 提取接下来的路径分量（如 `usr`、`bin` 等），并将该分量复制到 `name` 中，
/// 最后返回下一个未处理字符的位置索引。该函数通常用于分层遍历路径中的各级目录名。
///
/// # 流程解释
/// 1. 跳过当前的一个或多个 `'/'` 分隔符；
/// 2. 记录路径分量起始位置 `start`，然后向后扫描直到遇到下一个 `'/'` 或路径结尾（0u8）；
/// 3. 将路径分量复制到 `name` 中（若过长则截断），并以 0 结尾；
/// 4. 再次跳过后续的 `'/'`，准备下一次解析；
/// 5. 返回当前位置的索引，供下一次解析使用。
///
/// # 参数
/// - `path`: 路径字节数组，需以 `0u8` 结尾（如 `b"/usr/bin/test\0"`）；
/// - `cur`: 当前解析起点的位置索引；
/// - `name`: 输出参数，用于存储解析出的路径分量，最大长度为 `MAX_DIR_SIZE`；
///
/// # 返回值
/// - 返回跳过当前路径分量后新的偏移量索引；
/// - 若当前位置正好是路径结尾（`0u8`），则返回 0，表示解析结束；
///
/// # 可能的错误
/// - 若 `cur` 越界或未以 `0u8` 结尾，可能触发 panic（由调用者负责保证）；
/// - 若路径分量长度超过 `MAX_DIR_SIZE - 1`，将被自动截断；
///
/// # 安全性
/// - 使用了 `unsafe` 的指针拷贝：
///   - `ptr::copy(path.as_ptr().offset(...), name.as_mut_ptr(), count)`；
///   - 但前提已确保 `count` 不超过 `name` 缓冲区长度，且 `path` 为合法切片，
///     因此整体是受控的 unsafe 操作；
/// - 要求调用者确保传入的 `path[cur]` 不会越界读取；

fn skip_path(path: &[u8], mut cur: usize, name: &mut [u8; MAX_DIR_SIZE]) -> usize {
    // skip preceding b'/'
    while path[cur] == b'/' {
        cur += 1;
    }
    if path[cur] == 0 {
        return 0
    }

    let start = cur;
    while path[cur] != b'/' && path[cur] != 0 {
        cur += 1;
    }
    let mut count = cur - start;
    if count >= name.len() {
        // debug_assert!(false);
        count = name.len() - 1;
    }
    unsafe { ptr::copy(path.as_ptr().offset(start as isize), name.as_mut_ptr(), count); }
    name[count] = 0;

    // skip succeeding b'/'
    while path[cur] == b'/' {
        cur += 1;
    }
    cur
}

/// 表示内核中活动的 inode 句柄，由 inode 缓存（`InodeCache`）统一分配和管理。
///
/// # 结构体用途
/// `Inode` 结构体并不直接包含 inode 的全部数据，而是作为一个轻量级句柄，
/// 间接引用 inode 缓存池中的真实数据与元信息。它通过 `index` 字段索引 `ICACHE` 中的具体位置，
/// 并配合引用计数实现 inode 的共享与回收。所有文件、目录、设备节点的访问都通过该结构体进行抽象。
///
/// 实际数据访问需通过 `.lock()` 方法获取受保护的 [`InodeData`]。
#[derive(Debug)]
pub struct Inode {
    /// 设备号，标识该 inode 所在的磁盘或设备。
    dev: u32,

    /// inode 编号，唯一标识该设备上的一个 inode。
    inum: u32,

    /// 在全局 inode 缓存中的索引位置（用于访问缓存中对应的 `meta` 和 `data` 条目）。
    index: usize,
}


impl Clone for Inode {
    fn clone(&self) -> Self {
        ICACHE.dup(self)
    }
}

impl Inode {
    /// 加锁当前 inode，并在必要时从磁盘加载其内容。
    ///
    /// # 功能说明
    /// 本函数用于访问 inode 的数据内容。在首次访问该 inode 时（即尚未加载进缓存），
    /// 它会从磁盘中读取 inode 对应的结构体并写入缓存，并设置有效标志；
    /// 若 inode 内容已加载过，则直接返回锁保护的 [`InodeData`] 引用。
    ///
    /// 返回值是受 [`SleepLock`] 保护的数据结构，用于后续对 inode 的安全访问（如读取、写入、更新等）。
    ///
    /// # 流程解释
    /// 1. 获取当前 inode 在缓存中对应的 `SleepLock<InodeData>` 锁；
    /// 2. 若该条目尚未加载（`valid == None`），则从磁盘读取 inode 内容并填入缓存：
    ///     - 通过 `BCACHE.bread` 读取 inode 所在磁盘块；
    ///     - 计算其在块内的偏移；
    ///     - 使用 unsafe 指针读取对应的 [`DiskInode`]；
    ///     - 设置缓存内容，并标记为有效；
    ///     - 若 inode 类型为空（`InodeType::Empty`），触发 panic；
    /// 3. 返回获取到的 `SleepLockGuard` 以访问 inode 数据。
    ///
    /// # 参数
    /// - `self`: 当前 inode 句柄，提供 dev/inum/index 信息以定位 inode 缓存项；
    ///
    /// # 返回值
    /// 返回 [`SleepLockGuard<'a, InodeData>`]，表示当前 inode 的受保护数据引用；
    ///
    /// # 可能的错误
    /// - 若 inode 在磁盘上类型为 `InodeType::Empty`，表示逻辑上未初始化，将触发 panic；
    /// - 若 inode 编号非法或超出块内偏移范围，可能造成 undefined behavior（需调用者保证合法性）；
    ///
    /// # 安全性
    /// - 使用了 unsafe 指针访问磁盘块内的 inode 结构：
    ///     - `raw_data()` 提供原始块地址，之后通过偏移访问对应 inode；
    ///     - 读出的指针不会越界，前提是 `SUPER_BLOCK.locate_inode()` 与 `locate_inode_offset()` 保证正确性；
    /// - 整体逻辑受 `SleepLock` 保护，确保并发访问时的数据一致性；
    /// - 若在无事务保护下使用该 inode（尤其进行写操作），需由外部调用者保证一致性与原子性；
    pub fn lock<'a>(&'a self) -> SleepLockGuard<'a, InodeData> {
        let mut guard = ICACHE.data[self.index].lock();

        if guard.valid.is_none() {
            let buf = BCACHE.bread(self.dev, unsafe { SUPER_BLOCK.locate_inode(self.inum) });
            let offset = locate_inode_offset(self.inum);
            let dinode = unsafe { (buf.raw_data() as *const DiskInode).offset(offset) };
            guard.dinode = unsafe { ptr::read(dinode) };
            drop(buf);
            guard.valid = Some((self.dev, self.inum));
            if guard.dinode.itype == InodeType::Empty {
                panic!("inode: lock an empty inode");
            }
        }

        guard
    }
}

impl Drop for Inode {
    /// Done with this inode.
    /// If this is the last reference in the inode cache, then is might be recycled.
    /// Further, if this inode has no links anymore, free this inode in the disk.
    fn drop(&mut self) {
        ICACHE.put(self);
    }
}

/// 表示 inode 缓存中每个条目的元信息，用于唯一标识并管理 inode 的生命周期。
///
/// # 结构体用途
/// `InodeMeta` 是 `InodeCache` 中 `meta` 数组的元素类型，用于记录每个 inode 缓存项的基础状态，
/// 包括其所属设备、在设备上的 inode 编号以及当前引用计数。该结构不包含 inode 的实际数据内容，
/// 而仅用于在缓存中查找、判重、分配及回收 inode。
///
/// 内核通过 `refs` 字段控制 inode 生命周期管理，引用计数为 0 时表示该项可重用。
struct InodeMeta {
    /// 设备号，标识该 inode 所在的磁盘设备。
    dev: u32,

    /// inode 编号，在设备内部唯一标识一个 inode。
    inum: u32,

    /// 当前引用计数，用于控制该 inode 缓存项的占用与释放。
    /// 为 0 表示该项未被使用；大于 0 表示有活动引用。
    refs: usize,
}


impl InodeMeta {
    const fn new() -> Self {
        Self {
            dev: 0,
            inum: 0,
            refs: 0,
        }
    }
}

/// 表示 inode 在内存中的完整副本，包含从磁盘加载的 inode 数据及其有效性标志。
///
/// # 结构体用途
/// `InodeData` 是对磁盘上 inode (`DiskInode`) 的内存表示，
/// 用于缓存 inode 内容并支持对其进行读取、修改、写回等操作。
/// 它通常与 [`SleepLock`] 一起受保护，以保证多线程环境下的安全访问。
///
/// 每个活动的 inode 缓存项都包含一个 `InodeData`，其生命周期由 `InodeCache` 管理。
#[derive(Debug)]
pub struct InodeData {
    /// 标记该 inode 是否已从磁盘加载，并记录其 `(dev, inum)` 信息。
    /// - `None` 表示当前缓存内容无效；
    /// - `Some((dev, inum))` 表示已加载且可用。
    valid: Option<(u32, u32)>,

    /// 磁盘 inode 的实际内容副本，包括类型、链接数、文件大小及数据块地址等字段。
    /// 该字段保存的是从磁盘读入的结构体，并可被修改和写回。
    dinode: DiskInode,
}


impl InodeData {
    const fn new() -> Self {
        Self {
            valid: None,
            dinode: DiskInode::new(),
        }
    }

    /// Get inode dev and inum.
    #[inline]
    pub fn get_dev_inum(&self) -> (u32, u32) {
        self.valid.unwrap()
    }

    /// Get inode type.
    #[inline]
    pub fn get_itype(&self) -> InodeType {
        self.dinode.itype
    }

    /// Get device number.
    #[inline]
    pub fn get_devnum(&self) -> (u16, u16) {
        (self.dinode.major, self.dinode.minor)
    }

    /// Increase the hard link by 1.
    #[inline]
    pub fn link(&mut self) {
        self.dinode.nlink += 1;
    }

    /// Decrease the hard link by 1.
    pub fn unlink(&mut self) {
        self.dinode.nlink -= 1;
    }

    /// 丢弃当前 inode 所有的数据块，并将其大小清零。
    ///
    /// # 功能说明
    /// `truncate` 用于回收 inode 占用的所有数据块资源，包括直接块和间接块，
    /// 并将文件大小设置为 0，从而实现对 inode 内容的完全清除，通常用于文件删除或重置场景。
    ///
    /// # 流程解释
    /// 1. 获取当前 inode 所属设备号 `dev`；
    /// 2. 遍历所有直接块（`dinode.addrs[0..NDIRECT]`）：
    ///     - 若对应块号非 0，则调用 `bm_free` 释放该块；
    ///     - 将地址清零；
    /// 3. 若存在间接块（`dinode.addrs[NDIRECT]` 非 0）：
    ///     - 读取该块为指针数组；
    ///     - 遍历数组并释放所有非 0 块；
    ///     - 释放间接块本身；
    ///     - 清除间接块地址；
    /// 4. 将 inode 的文件大小字段 `size` 设置为 0；
    /// 5. 调用 `update()` 将清空后的 inode 写回磁盘。
    ///
    /// # 参数
    /// - `self`: 当前被操作的 [`InodeData`]，必须已从磁盘加载且 `valid` 字段为 `Some`。
    ///
    /// # 返回值
    /// 无返回值；操作成功后，该 inode 所引用的所有数据块将被释放。
    ///
    /// # 可能的错误
    /// - 若 `valid` 字段为 `None`，`unwrap()` 会 panic（调用者必须保证该 inode 有效）；
    /// - 如果某些块号非法或未正确初始化，`bm_free` 可能引发错误（假设其内部实现包含断言）；
    ///
    /// # 安全性
    /// - 使用了 `unsafe` 指针访问间接块内容（`ptr::read`），但已由 `BCACHE.bread` 提供合法内存区域；
    /// - 所有内存写操作均在受控上下文下进行，无悬垂指针或越界访问；
    /// - 调用者需保证在事务上下文中调用该函数（与日志一致性相关）；
    pub fn truncate(&mut self) {
        let (dev, _) = *self.valid.as_ref().unwrap();

        // direct block
        for i in 0..NDIRECT {
            if self.dinode.addrs[i] > 0 {
                bm_free(dev, self.dinode.addrs[i]);
                self.dinode.addrs[i] = 0;
            }
        }

        // indirect block
        if self.dinode.addrs[NDIRECT] > 0 {
            let buf = BCACHE.bread(dev, self.dinode.addrs[NDIRECT]);
            let buf_ptr = buf.raw_data() as *const BlockNo;
            for i in 0..NINDIRECT {
                let bn = unsafe { ptr::read(buf_ptr.offset(i as isize)) };
                if bn > 0 {
                    bm_free(dev, bn);
                }
            }
            drop(buf);
            bm_free(dev, self.dinode.addrs[NDIRECT]);
            self.dinode.addrs[NDIRECT] = 0;
        }

        self.dinode.size = 0;
        self.update();
    }

    /// 将已修改的内存中 inode 信息写回磁盘。
    ///
    /// # 功能说明
    /// `update` 用于同步内存中的 [`InodeData`] 到磁盘上的 [`DiskInode`]。
    /// 每当 inode 的元数据（如类型、大小、链接计数或数据块地址）发生更改时，
    /// 应调用本函数将其写入相应磁盘位置，以确保文件系统状态持久化。
    ///
    /// # 流程解释
    /// 1. 解包 `valid` 字段，获取设备号和 inode 编号；
    /// 2. 通过 `SUPER_BLOCK.locate_inode()` 获取该 inode 在磁盘中的块号；
    /// 3. 使用 `BCACHE.bread()` 读取该块；
    /// 4. 使用 `locate_inode_offset()` 计算该 inode 在块内的偏移；
    /// 5. 将内存中的 `self.dinode` 内容写入该偏移位置；
    /// 6. 通过 `LOG.write()` 将更新的缓冲区加入日志系统，确保之后写入磁盘。
    ///
    /// # 参数
    /// - `self`: 当前正在更新的 [`InodeData`]，要求其 `valid` 字段为 `Some`，即已成功加载；
    ///
    /// # 返回值
    /// 无返回值。操作完成后，内存中的 inode 状态将被持久化到磁盘中。
    ///
    /// # 可能的错误
    /// - 若 `valid` 为 `None`，调用 `.unwrap()` 会触发 panic；
    /// - 若 inode 编号越界或定位信息错误，可能导致对非法内存写入（由调用者负责确保合法性）；
    ///
    /// # 安全性
    /// - 使用了 `unsafe` 指针将 `DiskInode` 写入磁盘块缓冲区：
    ///   - `raw_data_mut()` 提供原始写入地址；
    ///   - 使用 `ptr::write()` 直接写入结构体；
    /// - 此写入操作是受控的，前提是偏移定位和缓冲区指针由内核逻辑正确计算；
    /// - 调用者需确保该操作位于日志事务内部（`LOG.begin_op()` / `end_op()`），以保障写入的原子性和恢复能力；
    pub fn update(&mut self) {
        let (dev, inum) = *self.valid.as_ref().unwrap();

        let mut buf = BCACHE.bread(dev, unsafe { SUPER_BLOCK.locate_inode(inum) });
        let offset = locate_inode_offset(inum);
        let dinode = unsafe { (buf.raw_data_mut() as *mut DiskInode).offset(offset) };
        unsafe { ptr::write(dinode, self.dinode) };
        LOG.write(buf);
    }

    /// 从磁盘中读取 inode 对应的数据内容，并拷贝到指定地址空间中。
    ///
    /// # 功能说明
    /// `iread` 实现对 inode 文件数据的顺序读取，适用于将文件内容读取到用户空间或内核空间缓冲区。
    /// 它根据 inode 的数据块映射表，逐块读取数据，并通过地址抽象 [`Address`] 将其拷贝到目标地址中。
    ///
    /// # 流程解释
    /// 1. 检查 `offset + count` 是否溢出或超过当前 inode 文件大小；
    /// 2. 将偏移量 `offset` 和长度 `count` 转换为字节数，确定起始块编号 `block_base` 和块内偏移 `block_offset`；
    /// 3. 在循环中：
    ///     - 根据 `block_base` 使用 `map_blockno()` 获取磁盘块号；
    ///     - 调用 `BCACHE.bread()` 读取该块；
    ///     - 从块数据中按需偏移并读取 `read_count` 字节到 `dst` 所指定的位置；
    ///     - 更新剩余读取长度与目标地址，继续下一块；
    /// 4. 所有块读取完毕后返回 `Ok(())`。
    ///
    /// # 参数
    /// - `dst`: 目标地址，表示读取结果要写入的位置，可为用户空间或内核空间地址（通过 [`Address`] 抽象）；
    /// - `offset`: 从文件中开始读取的偏移字节数；
    /// - `count`: 要读取的字节数；
    ///
    /// # 返回值
    /// - 成功时返回 `Ok(())`，表示所有请求的数据已成功读取；
    /// - 若 `offset + count` 溢出或超出文件大小，则返回 `Err(())`；
    ///
    /// # 可能的错误
    /// - 当 `offset + count` 溢出（`u32::MAX`）或超出 inode 实际文件大小 `dinode.size`，返回 `Err(())`；
    /// - 如果在读取过程中 `copy_out` 失败（如无效地址或越界），也会提前返回 `Err(())`；
    ///
    /// # 安全性
    /// - 使用 `unsafe` 的指针偏移访问磁盘块数据，但该地址由 `BCACHE` 提供，确保在有效内存范围内；
    /// - 所有对目标地址 `dst` 的访问通过安全封装的 [`Address::copy_out`] 实现，调用方需保证地址有效；
    /// - 函数未修改 inode 状态，因此可安全并发只读调用；
    pub fn iread(&mut self, mut dst: Address, offset: u32, count: u32) -> Result<(), ()> {
        // check the reading content is in range
        let end = offset.checked_add(count).ok_or(())?;
        if end > self.dinode.size {
            return Err(())
        }

        let (dev, _) = *self.valid.as_ref().unwrap();
        let offset = offset as usize;
        let mut count = count as usize;
        let mut block_base = offset / BSIZE;
        let block_offset = offset % BSIZE;
        let mut read_count = min(BSIZE - block_offset, count);
        let mut block_offset = block_offset as isize;
        while count > 0 {
            let buf = BCACHE.bread(dev, self.map_blockno(block_base));
            let src_ptr = unsafe { (buf.raw_data() as *const u8).offset(block_offset) };
            dst.copy_out(src_ptr, read_count)?;
            drop(buf);

            count -= read_count;
            dst = dst.offset(read_count);
            block_base += 1;
            block_offset = 0;
            read_count = min(BSIZE, count);
        }
        Ok(())
    }

    /// 尝试从 inode 中读取尽可能多的数据，返回实际读取的字节数。
    ///
    /// # 功能说明
    /// `try_iread` 是 [`iread`] 的宽松版本：即使读取范围超过文件末尾，也不会报错，
    /// 而是最多读取到文件末尾为止。适用于用户指定读取长度，但不确定实际文件大小的场景。
    ///
    /// # 流程解释
    /// 1. 若 `offset` 已超过 inode 文件实际大小，则返回 `Ok(0)` 表示无需读取；
    /// 2. 检查 `offset + count` 是否发生整数溢出，若溢出则返回 `Err(())`；
    /// 3. 计算实际可读取的长度 `actual_count = min(count, dinode.size - offset)`；
    /// 4. 调用 `iread` 执行读取操作；
    /// 5. 若成功，返回 `Ok(actual_count)`，表示实际读取的字节数。
    ///
    /// # 参数
    /// - `dst`: 目标地址，表示读取结果写入的内存位置，封装为 [`Address`]；
    /// - `offset`: 文件内起始读取偏移（单位：字节）；
    /// - `count`: 期望读取的最大字节数；
    ///
    /// # 返回值
    /// - `Ok(n)`：成功读取 `n` 字节（`n <= count`）；
    /// - `Ok(0)`：偏移已超出文件范围，无需读取；
    /// - `Err(())`：发生整数溢出或读取失败；
    ///
    /// # 可能的错误
    /// - `offset + count` 发生 `u32` 溢出时返回 `Err(())`；
    /// - 若 `iread` 过程中出现读失败（如目标地址无效），则返回 `Err(())`；
    ///
    /// # 安全性
    /// - 所有数据访问均通过封装好的 `iread` 完成，`try_iread` 本身不涉及任何 unsafe 操作；
    /// - 调用方需确保 `dst` 地址合法，以避免读取数据写入非法内存；
    pub fn try_iread(&mut self, dst: Address, offset: u32, count: u32) -> Result<u32, ()> {
        // check the reading content is in range
        if offset > self.dinode.size {
            return Ok(0)
        }
        let end = offset.checked_add(count).ok_or(())?;
        let actual_count = if end > self.dinode.size {
            self.dinode.size - offset
        } else {
            count
        };
        self.iread(dst, offset, actual_count)?;
        Ok(actual_count)
    }

    /// 将数据写入 inode 对应的文件内容区域，要求必须完整写入全部字节。
    ///
    /// # 功能说明
    /// `iwrite` 是 [`try_iwrite`] 的封装版本，用于执行强保证的写入操作。
    /// 它仅在全部 `count` 字节成功写入的情况下才返回 `Ok(())`，否则视为失败返回 `Err(())`。
    /// 该函数适用于需要原子写入完整数据的场景，例如写入目录项或设备节点信息等。
    ///
    /// # 流程解释
    /// 1. 调用 [`try_iwrite`] 执行写入操作；
    /// 2. 检查实际写入的字节数是否等于请求的 `count`；
    /// 3. 若相等，说明写入完整，返回 `Ok(())`；
    /// 4. 若不等或发生错误，返回 `Err(())` 表示写入失败。
    ///
    /// # 参数
    /// - `src`: 来源地址，封装为 [`Address`] 类型，表示用户空间或内核空间的起始地址；
    /// - `offset`: 文件内起始写入偏移（单位：字节），必须小于等于当前文件大小；
    /// - `count`: 需要写入的总字节数；
    ///
    /// # 返回值
    /// - `Ok(())`：表示请求的所有 `count` 字节已成功写入；
    /// - `Err(())`：写入部分失败或完全失败；
    ///
    /// # 可能的错误
    /// - 如果写入过程中发生地址非法、块映射失败或参数溢出，则返回 `Err(())`；
    /// - 如果写入不完整（即部分成功但总字节数不足），也会返回 `Err(())`；
    ///
    /// # 安全性
    /// - 本函数不涉及任何 `unsafe` 操作；
    /// - 安全性完全依赖于 [`try_iwrite`] 的实现；
    /// - 调用者应保证在日志事务中使用本函数，以避免一致性问题；
    pub fn iwrite(&mut self, src: Address, offset: u32, count: u32) -> Result<(), ()> {
        match self.try_iwrite(src, offset, count) {
            Ok(ret) => if ret == count { Ok(()) } else { Err(()) },
            Err(()) => Err(()),
        }
    }

    /// 尝试将数据写入 inode 所代表的文件内容区域，并返回实际写入的字节数。
    ///
    /// # 功能说明
    /// `try_iwrite` 实现将用户或内核地址空间中的数据写入 inode 所管理的文件数据区，  
    /// 会根据写入位置自动进行磁盘块分配并更新文件大小（如果写入超过原有大小）。
    /// 它允许部分写入，即使中途失败也会返回当前已写入的字节数。
    ///
    /// # 流程解释
    /// 1. 检查 `offset` 是否在当前文件大小范围内（不能写入文件尾后空洞）；
    /// 2. 检查 `offset + count` 是否会溢出或超过文件系统允许的最大文件大小；
    /// 3. 循环写入数据：
    ///     - 计算目标块号、块内偏移和可写字节数；
    ///     - 调用 `map_blockno()` 保证目标块已分配；
    ///     - 使用 `BCACHE.bread()` 读入目标块；
    ///     - 使用 `Address::copy_in()` 从 `src` 拷贝数据到块缓冲区；
    ///     - 写入后将该块加入日志系统（`LOG.write()`）；
    ///     - 更新剩余写入量、地址偏移；
    /// 4. 若写入过程扩展了文件大小，则更新 inode 的 `size` 并调用 `update()` 写回磁盘；
    /// 5. 返回成功写入的实际字节数。
    ///
    /// # 参数
    /// - `src`: 来源地址，数据将从此处拷贝到磁盘块中（支持用户/内核地址）；
    /// - `offset`: 文件内起始写入位置（单位：字节），必须不超过当前文件大小；
    /// - `count`: 期望写入的最大字节数；
    ///
    /// # 返回值
    /// - `Ok(n)`：成功写入了 `n` 字节（`n <= count`）；
    /// - `Err(())`：写入参数非法或地址错误导致完全失败；
    ///
    /// # 可能的错误
    /// - 若 `offset > inode.size`，即试图向尚未分配的空洞写入，将返回 `Err(())`；
    /// - 若 `offset + count` 溢出或超出 `MAX_FILE_SIZE`，将返回 `Err(())`；
    /// - 若 `copy_in` 拷贝失败（如地址无效或权限问题），会中断写入并返回已写部分；
    ///
    /// # 安全性
    /// - 使用 `unsafe` 指针操作将数据写入块缓冲区（`raw_data_mut().offset(...)`）；
    ///   前提是 `bread()` 已返回合法数据块，且偏移量已正确计算；
    /// - 所有外部数据来源都通过 `Address` 抽象，避免了裸指针的不安全访问；
    /// - 本函数修改了 inode 的数据块及文件大小，必须由事务机制（`LOG.begin_op()` / `end_op()`）包裹以确保一致性；
    pub fn try_iwrite(&mut self, mut src: Address, offset: u32, count: u32) -> Result<u32, ()> {
        // check the writing content is in range
        if offset > self.dinode.size {
            return Err(())
        }
        let end = offset.checked_add(count).ok_or(())? as usize;
        if end > MAX_FILE_SIZE {
            return Err(())
        }

        let (dev, _) = *self.valid.as_ref().unwrap();
        let mut block_base = (offset as usize) / BSIZE;
        let block_offset = (offset as usize) % BSIZE;
        let mut count = count as usize;
        let mut write_count = min(BSIZE - block_offset, count);
        let mut block_offset = block_offset as isize;
        while count > 0 {
            let mut buf = BCACHE.bread(dev, self.map_blockno(block_base));
            let dst_ptr = unsafe { (buf.raw_data_mut() as *mut u8).offset(block_offset) };
            if src.copy_in(dst_ptr, write_count).is_err() {
                break
            };
            LOG.write(buf);

            count -= write_count;
            src = src.offset(write_count);
            block_base += 1;
            block_offset = 0;
            write_count = min(BSIZE, count);
        }

        // end <= MAX_FILE_SIZE <= u32::MAX
        let size = (end - count) as u32;
        if size > self.dinode.size {
            self.dinode.size = size;
        }
        self.update();
        Ok(size-offset)
    }

    /// 填充指定的 [`FileStat`] 结构体，以反映当前 inode 的元数据信息。
    ///
    /// # 功能说明
    /// `istat` 用于获取当前 inode 的状态信息，包括设备号、inode 编号、类型、链接数和文件大小。
    /// 通常用于实现如 `stat` 系统调用或 `fstat` 接口，向用户空间或上层模块报告文件状态。
    ///
    /// # 流程解释
    /// 1. 解包 `valid` 字段，获取该 inode 所在设备号和编号；
    /// 2. 从 `dinode` 中读取文件类型、硬链接数量和大小；
    /// 3. 将上述信息写入传入的 `FileStat` 结构体中；
    ///
    /// # 参数
    /// - `stat`: 可变引用，用于输出 inode 的状态信息；
    ///
    /// # 返回值
    /// 无返回值，结果通过 `stat` 参数传出。
    ///
    /// # 可能的错误
    /// - 若 `self.valid` 为 `None`，表示该 inode 尚未被初始化或未从磁盘加载，将触发 panic；
    ///
    /// # 安全性
    /// - 本函数不涉及 `unsafe` 操作；
    /// - 仅读取结构体字段并写入 `FileStat`，不会造成任何副作用；
    /// - 调用者应确保该 inode 已被 `lock()` 加载并有效；
    pub fn istat(&self, stat: &mut FileStat) {
        let (dev, inum) = self.valid.unwrap();
        stat.dev = dev;
        stat.inum = inum;
        stat.itype = self.dinode.itype;
        stat.nlink = self.dinode.nlink;
        stat.size = self.dinode.size as u64;
    }

    /// 根据数据块逻辑编号返回其在磁盘中的物理块号，如有必要则分配新块。
    ///
    /// # 功能说明
    /// `map_blockno` 将 inode 内部逻辑数据块编号（`offset_bn`）映射为磁盘上的物理块号。
    /// 若对应的块尚未分配，则分配一个新的空闲块号并更新 inode 的地址表。该函数支持直接块和一级间接块两种地址模式。
    ///
    /// # 流程解释
    /// 1. 解包 `valid` 字段，获取该 inode 所在设备号；
    /// 2. 判断 `offset_bn` 是否落在直接块范围：
    ///     - 若落在前 `NDIRECT` 项，直接从 `dinode.addrs` 数组中读取；
    ///     - 若该项为 0，调用 `bm_alloc` 分配新块并记录；
    /// 3. 若落在间接块范围：
    ///     - 检查并分配间接块（`dinode.addrs[NDIRECT]`）；
    ///     - 读取间接块数据到缓冲区；
    ///     - 按偏移读取目标项，若为 0，则分配新块并写入；
    ///     - 返回最终的块号；
    /// 4. 若超过最大支持块数（直接 + 间接），触发 panic。
    ///
    /// # 参数
    /// - `offset_bn`: 数据块在 inode 中的逻辑块编号（从 0 开始）；
    ///
    /// # 返回值
    /// - 返回 `u32` 类型的物理块号（block number），表示在磁盘中的实际位置；
    ///
    /// # 可能的错误
    /// - 若 `offset_bn >= NDIRECT + NINDIRECT`，即超出 inode 支持的最大逻辑块数量，将触发 panic；
    /// - 若 `valid` 字段为 `None`，使用 `.unwrap()` 将导致 panic（调用者必须在有效 inode 上调用）；
    ///
    /// # 安全性
    /// - 使用了 `unsafe` 指针对磁盘块缓冲区进行偏移访问（`raw_data_mut()` 和 `ptr::read`/`ptr::write`）；
    ///   调用前已通过 `bread()` 获取了有效的磁盘块，因此指针操作在受控范围内；
    /// - 操作需要在日志事务中完成，以确保磁盘块分配与 inode 修改的一致性；
    fn map_blockno(&mut self, offset_bn: usize) -> u32 {
        let (dev, _) = *self.valid.as_ref().unwrap();
        if offset_bn < NDIRECT {
            // in direct block
            if self.dinode.addrs[offset_bn] == 0 {
                let free_bn = bm_alloc(dev);
                self.dinode.addrs[offset_bn] = free_bn;
                free_bn
            } else {
                self.dinode.addrs[offset_bn]
            }
        } else if offset_bn < NDIRECT + NINDIRECT {
            // in indirect block
            let count = (offset_bn - NDIRECT) as isize;

            let indirect_bn = if self.dinode.addrs[NDIRECT] == 0 {
                let free_bn = bm_alloc(dev);
                self.dinode.addrs[NDIRECT] = free_bn;
                free_bn
            } else {
                self.dinode.addrs[NDIRECT]
            };
            let mut indirect_buf = BCACHE.bread(dev, indirect_bn);
            let bn_ptr = unsafe { (indirect_buf.raw_data_mut() as *mut BlockNo).offset(count) };
            let bn = unsafe { ptr::read(bn_ptr) };
            if bn == 0 {
                let free_bn = bm_alloc(dev);
                unsafe { ptr::write(bn_ptr, free_bn); }
                LOG.write(indirect_buf);
                free_bn
            } else {
                drop(indirect_buf);
                bn
            }
        } else {
            panic!("queried offset_bn out of range");
        }
    }

    /// 在当前目录 inode 中查找指定名称的目录项（DirEntry），并返回其对应的 inode。
    ///
    /// # 功能说明
    /// `dir_lookup` 用于在目录 inode 中查找给定名称的目录项。若找到，则返回对应 inode；
    /// 若设置 `need_offset` 参数为 `true`，还会一并返回该目录项在目录文件中的偏移地址，用于后续修改或删除。
    /// 该函数用于实现路径解析、文件打开、目录项删除等功能的基础设施。
    ///
    /// # 流程解释
    /// 1. 解包 `valid` 字段以获取设备号，并确保该 inode 类型为 `Directory`；
    /// 2. 创建一个临时 `DirEntry` 缓冲区，用于逐个读取目录项；
    /// 3. 遍历当前目录数据区中所有目录项（每次步进一个目录项大小）：
    ///     - 调用 `iread` 读取目录项；
    ///     - 跳过 `inum == 0` 的空项；
    ///     - 将每个目录项的名称与输入 `name` 字节数组逐字节比较；
    ///     - 若完全匹配，返回匹配 inode 及其偏移量（若需要）；
    /// 4. 如果遍历结束仍未找到匹配项，则返回 `None`。
    ///
    /// # 参数
    /// - `name`: 待查找的文件名，长度为 `MAX_DIR_SIZE` 的字节数组；
    /// - `need_offset`: 布尔值，若为 `true`，则一并返回目录项在目录文件中的偏移量；
    ///
    /// # 返回值
    /// - `Some((inode, Some(offset)))`：找到匹配目录项，并返回 inode 及其偏移；
    /// - `Some((inode, None))`：找到匹配目录项，但调用方不需要偏移；
    /// - `None`：未找到匹配的目录项；
    ///
    /// # 可能的错误
    /// - 如果当前 inode 不是目录类型（即 `itype != InodeType::Directory`），会触发 panic；
    /// - 如果 `self.valid` 为 `None`，在 `.unwrap()` 处 panic（调用前需确保 inode 已加载）；
    /// - 如果 `iread` 读取失败，也会触发 panic（假定数据一致性已通过日志系统保障）；
    ///
    /// # 安全性
    /// - 本函数不涉及 `unsafe` 操作；
    /// - 所有数据读取通过封装好的 `iread` 完成，避免直接操作指针；
    /// - 调用者必须确保在持有 `InodeData` 锁的前提下调用本函数，防止并发访问目录内容；
    fn dir_lookup(&mut self, name: &[u8; MAX_DIR_SIZE], need_offset: bool) -> Option<(Inode, Option<u32>)> {
        let (dev, _) = *self.valid.as_ref().unwrap();
        debug_assert!(dev != 0);
        if self.dinode.itype != InodeType::Directory {
            panic!("inode type not dir");
        }

        let de_size = mem::size_of::<DirEntry>();
        let mut dir_entry = DirEntry::empty();
        let dir_entry_ptr = Address::KernelMut(&mut dir_entry as *mut _ as *mut u8);
        for offset in (0..self.dinode.size).step_by(de_size) {
            self.iread(dir_entry_ptr, offset, de_size as u32).expect("read dir entry");
            if dir_entry.inum == 0 {
                continue;
            }
            for i in 0..MAX_DIR_SIZE {
                if dir_entry.name[i] != name[i] {
                    break;
                }
                if dir_entry.name[i] == 0 {
                    return Some((ICACHE.get(dev, dir_entry.inum as u32),
                        if need_offset { Some(offset) } else { None }))
                }
            }
        }

        None
    }

    /// 向当前目录 inode 写入一个新的目录项 [`DirEntry`]。
    ///
    /// # 功能说明
    /// `dir_link` 用于在目录类型的 inode 中插入一个新的目录项，建立名称到 inode 编号的映射。
    /// 常用于创建新文件或子目录时，将其添加到父目录中。插入前会检查该名称是否已存在，若存在则返回错误。
    ///
    /// # 流程解释
    /// 1. 检查 `inum` 是否超过 `u16::MAX`，超出则 panic（当前目录项结构只支持 `u16` 编号）；
    /// 2. 调用 `dir_lookup` 判断是否已有相同名称的目录项，若存在则返回 `Err(())`；
    /// 3. 遍历当前目录文件的内容，查找空闲目录项（`inum == 0`）位置；
    ///     - 若找到空槽，则记录其偏移 `offset`；
    ///     - 若没有空槽，则使用文件末尾偏移；
    /// 4. 构造一个新的 `DirEntry`，填入名称与 inode 编号；
    /// 5. 调用 `iwrite` 将新目录项写入到偏移位置；
    /// 6. 写入成功后返回 `Ok(())`。
    ///
    /// # 参数
    /// - `name`: 目录项的名称，最大长度为 `MAX_DIR_SIZE`，必须为完整的字节数组；
    /// - `inum`: 需要链接的目标 inode 编号（必须小于等于 `u16::MAX`）；
    ///
    /// # 返回值
    /// - `Ok(())`：插入成功；
    /// - `Err(())`：已存在同名目录项，插入失败；
    ///
    /// # 可能的错误
    /// - `inum` 大于 `u16::MAX` 将触发 panic；
    /// - 若 `iwrite` 写入目录项失败（如日志未开启或块映射失败），将 panic；
    /// - 若 `iread` 读取目录项失败，也可能触发 panic；
    ///
    /// # 安全性
    /// - 使用了 unsafe 指针进行结构体地址转换（`as *mut u8` / `as *const u8`），但访问均由封装的地址类型 `Address` 管理；
    /// - 依赖外部确保当前 inode 为目录类型，且处于事务保护中（如 `LOG.begin_op()` / `end_op()`）；
    /// - 函数内部未进行目录类型校验，调用者需保证 `self.dinode.itype == InodeType::Directory`；
    pub fn dir_link(&mut self, name: &[u8; MAX_DIR_SIZE], inum: u32) -> Result<(), ()> {
        if inum > u16::MAX as u32 {
            panic!("inum {} too large", inum);
        }
        let inum = inum as u16;

        // the entry should not be present
        if self.dir_lookup(name, false).is_some() {
            // auto drop the returned inode
            return Err(())
        }

        // allocate a dir entry
        let de_size = mem::size_of::<DirEntry>() as u32;
        let mut dir_entry = DirEntry::empty();
        let dir_entry_ptr = Address::KernelMut(&mut dir_entry as *mut _ as *mut u8);
        let mut offset = self.dinode.size;
        for off in (0..self.dinode.size).step_by(de_size as usize) {
            self.iread(dir_entry_ptr, off, de_size).expect("read dir entry");
            if dir_entry.inum == 0 {
                offset = off;
                break
            }
        }

        assert_eq!(offset % de_size, 0);
        dir_entry.name.copy_from_slice(name);
        dir_entry.inum = inum;
        let dir_entry_ptr = Address::Kernel(&dir_entry as *const _ as *const u8);
        if self.iwrite(dir_entry_ptr, offset, de_size).is_err() {
            panic!("inode write error");
        }

        Ok(())
    }

    /// 从当前目录中取消指定名称的目录项链接，并更新对应 inode 的链接计数。
    ///
    /// # 功能说明
    /// `dir_unlink` 用于在目录中删除指定名称的目录项，相当于执行 `unlink()` 或 `rmdir()` 操作的一部分。
    /// 它会将目录项清空，并根据文件类型和链接数更新对应 inode 的引用计数。对于目录，要求其内容必须为空。
    /// 该函数必须在日志事务（`LOG.begin_op()` / `end_op()`）中调用以确保一致性。
    ///
    /// # 流程解释
    /// 1. 检查被删除名称是否为特殊目录项 `"."` 或 `".."`，禁止删除这两项，返回错误；
    /// 2. 调用 `dir_lookup` 查找对应目录项及其偏移；
    /// 3. 锁住目标 inode，验证其链接计数 `nlink >= 1`，否则 panic；
    /// 4. 若该 inode 为目录类型，需检查其内容是否为空（调用 `dir_is_empty()`）；
    /// 5. 构造空目录项 `DirEntry::empty()` 并使用 `iwrite` 将其覆盖原目录项位置；
    /// 6. 若目标为目录类型，当前目录需减少一个链接计数（表示去掉 `..`）；
    /// 7. 目标 inode 的链接计数减一，并更新写回；
    /// 8. 操作成功，返回 `Ok(())`。
    ///
    /// # 参数
    /// - `name`: 要取消链接的目录项名称（完整 `MAX_DIR_SIZE` 字节数组）；
    ///
    /// # 返回值
    /// - `Ok(())`：取消链接成功；
    /// - `Err(())`：目录项不存在、为特殊目录项或目录非空；
    ///
    /// # 可能的错误
    /// - 若名称为 `"."` 或 `".."`，将返回 `Err(())`；
    /// - 若未找到对应目录项或 offset 不可用，将返回 `Err(())`；
    /// - 若试图删除非空目录，将返回 `Err(())`；
    /// - 若目标 inode 的 `nlink == 0`，将 panic（表示文件系统状态异常）；
    /// - 若 `iwrite` 写入空目录项失败，将 panic；
    ///
    /// # 安全性
    /// - 本函数使用封装的 `Address` 类型进行数据写入，不涉及裸指针；
    /// - 通过 `SleepLock` 保护所有 inode 操作，确保并发安全；
    /// - 函数需在日志事务内调用，以确保对目录结构和 inode 的修改具有原子性和可恢复性；
    pub fn dir_unlink(&mut self, name: &[u8; MAX_DIR_SIZE]) -> Result<(), ()> {
        // the name should not be . and ..
        if name[0] == b'.' && (name[1] == 0 || (name[1] == b'.' && name[2] == 0)) {
            return Err(())
        }

        // lookup the entry correspond to the name
        let inode: Inode;
        let offset: u32;
        match self.dir_lookup(&name, true) {
            Some((i, Some(off))) => {
                inode = i;
                offset = off;
            },
            _ => return Err(()),
        }

        // check the entry
        let mut idata = inode.lock();
        if idata.dinode.nlink < 1 {
            panic!("entry inode's link is zero");
        }
        if idata.dinode.itype == InodeType::Directory && !idata.dir_is_empty() {
            return Err(())
        }

        // empty the entry
        let de_size = mem::size_of::<DirEntry>() as u32;
        let dir_entry = DirEntry::empty();
        let dir_entry_ptr = Address::Kernel(&dir_entry as *const DirEntry as *const u8);
        if self.iwrite(dir_entry_ptr, offset, de_size).is_err() {
            panic!("cannot write entry previously read");
        }

        // decrement some links
        if idata.dinode.itype == InodeType::Directory {
            self.dinode.nlink -= 1;
            self.update();
        }
        idata.dinode.nlink -= 1;
        idata.update();
        
        Ok(())
    }

    /// 判断当前目录 inode 是否为空目录（除去 `.` 和 `..` 之外无其他目录项）。
    ///
    /// # 功能说明
    /// `dir_is_empty` 用于判断当前 inode（必须为目录）是否为空目录。
    /// 在执行 `rmdir` 或目录解除链接操作前，需要保证目录中除 `.` 和 `..` 以外没有其他条目，以防误删非空目录。
    ///
    /// # 流程解释
    /// 1. 计算目录项的大小 `de_size`，并创建一个空的 `DirEntry` 缓冲区；
    /// 2. 从偏移量 `2 * de_size` 开始遍历目录（跳过 `.` 和 `..`）；
    /// 3. 每次循环读取一个目录项（使用 `iread`）：
    ///     - 若 `iread` 失败，触发 panic（表明磁盘数据异常）；
    ///     - 若 `dir_entry.inum != 0`，说明该目录项有效，返回 `false` 表示目录非空；
    /// 4. 遍历结束后未发现有效条目，返回 `true` 表示目录为空。
    ///
    /// # 参数
    /// - `self`: 当前被检查的 inode，调用前应确保其为 `Directory` 类型；
    ///
    /// # 返回值
    /// - `true`：表示该目录中除 `.` 和 `..` 外无其他有效目录项；
    /// - `false`：表示该目录中包含其他目录项，非空；
    ///
    /// # 可能的错误
    /// - 若 `iread` 在读取目录项过程中失败，会触发 panic（表示目录数据结构损坏或读取失败）；
    ///
    /// # 安全性
    /// - 使用封装好的 `Address::KernelMut` 进行内核地址空间数据访问，未涉及裸指针操作；
    /// - 该函数不会修改 inode 状态，适合在持有只读锁的上下文中调用；
    /// - 假设目录项结构合法，文件系统处于一致状态（否则 `iread` 会 panic）；
    fn dir_is_empty(&mut self) -> bool {
        let de_size = mem::size_of::<DirEntry>() as u32;
        let mut dir_entry = DirEntry::empty();
        let dir_entry_ptr = &mut dir_entry as *mut DirEntry;
        let dir_entry_addr = Address::KernelMut(dir_entry_ptr as *mut u8);
        for offset in ((2*de_size)..(self.dinode.size)).step_by(de_size as usize) {
            if self.iread(dir_entry_addr, offset, de_size).is_err() {
                panic!("read dir entry");
            }
            if dir_entry.inum != 0 {
                return false
            }
        }

        return true
    }
}

/// Number of inodes in a single block.
pub const IPB: usize = BSIZE / mem::size_of::<DiskInode>();

/// Given an inode number.
/// Calculate the offset index of this inode inside the block. 
#[inline]
pub fn locate_inode_offset(inum: u32) -> isize {
    (inum as usize % IPB) as isize
}

/// Check several requirements that inode struct should satisify.
pub fn icheck() {
    debug_assert_eq!(mem::align_of::<BufData>() % mem::align_of::<DiskInode>(), 0);

    // LTODO - replace some u32 to type alias BlockNo
    debug_assert_eq!(mem::align_of::<BufData>() % mem::align_of::<BlockNo>(), 0);
    debug_assert_eq!(mem::size_of::<BlockNo>(), mem::size_of::<u32>());
    debug_assert_eq!(mem::align_of::<BlockNo>(), mem::align_of::<u32>());

    debug_assert_eq!(mem::align_of::<BufData>() % mem::align_of::<DirEntry>(), 0);

    debug_assert!(MAX_FILE_SIZE <= u32::MAX as usize);
}

type BlockNo = u32;

/// 表示文件或目录的状态信息，用于向用户空间或上层模块报告 inode 的元数据。
///
/// # 结构体用途
/// `FileStat` 是对内核中 inode 元信息的抽象表示，通常用于实现系统调用 `stat` 或 `fstat`，
/// 供用户程序获取文件的基本属性，如设备号、inode 编号、类型、链接数和大小。
/// 它是用户空间和内核空间之间传递文件状态的标准结构体。
#[repr(C)]
#[derive(Debug)]
pub struct FileStat {
    /// 文件所在的设备编号（对应 block 设备号）。
    dev: u32,

    /// 文件的 inode 编号，唯一标识该设备上的一个文件。
    inum: u32,

    /// 文件类型，如普通文件、目录或设备节点。
    itype: InodeType,

    /// 硬链接计数，表示该 inode 被多少个目录项引用。
    nlink: u16,

    /// 文件的总大小（以字节为单位）。
    size: u64,
}


impl FileStat {
    pub const fn uninit() -> Self {
        Self {
            dev: 0,
            inum: 0,
            itype: InodeType::Empty,
            nlink: 0,
            size: 0,
        }
    }
}

/// 磁盘上的 inode 结构体，用于描述文件的元信息与数据块映射信息。
///
/// # 结构体用途
/// `DiskInode` 是文件系统中每个 inode 在磁盘上的持久化表示，
/// 存储了文件类型、设备信息、链接计数、文件大小以及数据块地址等内容。
/// 它是文件系统的核心结构之一，支持普通文件、目录、设备节点等多种类型的文件。
///
/// 此结构体通常通过块缓存 (`BufData`) 进行加载和修改，并由 `InodeData` 封装为内存中的表示。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DiskInode {
    /// 文件类型。
    /// - `Empty`：未使用（0）
    /// - `File`：普通文件（1）
    /// - `Directory`：目录（2）
    /// - `Device`：设备节点（3）
    itype: InodeType,

    /// 主设备号，仅对设备文件有效（用于识别驱动）。
    major: u16,

    /// 次设备号，仅对设备文件有效。
    minor: u16,

    /// 硬链接计数，表示该 inode 被多少个目录项引用。
    nlink: u16,

    /// 文件的实际字节大小。
    size: u32,

    /// 数据块地址数组：
    /// - 前 `NDIRECT` 项为直接块地址；
    /// - 最后一项为一级间接块地址（若启用）；
    addrs: [u32; NDIRECT + 1],
}

impl DiskInode {
    const fn new() -> Self {
        Self {
            itype: InodeType::Empty,
            major: 0,
            minor: 0,
            nlink: 0,
            size: 0,
            addrs: [0; NDIRECT + 1],
        }
    }

    /// If the [`DiskInode`] is free, i.e., its type is [`InodeType::Empty`],
    /// allocate it by setting its itype.
    pub fn try_alloc(&mut self, itype: InodeType) -> Result<(), ()> {
        if self.itype == InodeType::Empty {
            unsafe { ptr::write_bytes(self, 0, 1); }
            self.itype = itype;
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Inode type.
#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InodeType {
    Empty = 0,
    Directory = 1,
    File = 2,
    Device = 3,
}

/// 磁盘上的目录项结构体，用于表示目录中的单个文件或子目录的名称与 inode 映射关系。
///
/// # 结构体用途
/// `DirEntry` 是目录文件的数据结构单元，每个目录文件由若干个 `DirEntry` 组成。
/// 它用于维护文件名与 inode 编号之间的映射关系，是路径解析、文件创建与删除等操作的基础。
/// 当读取目录内容或插入/删除目录项时，系统会以 `DirEntry` 为基本单位进行处理。
#[repr(C)]
struct DirEntry {
    /// 对应目标文件或子目录的 inode 编号。
    /// 为 0 表示该目录项为空（可复用）。
    inum: u16,

    /// 目录项对应的文件名，长度不超过 `MAX_DIR_SIZE`，以 0 结尾（C 字符串风格）。
    name: [u8; MAX_DIR_SIZE],
}


impl DirEntry {
    const fn empty() -> Self {
        Self {
            inum: 0,
            name: [0; MAX_DIR_SIZE],
        }
    }
}
