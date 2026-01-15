use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::cmp::min;
use core::convert::TryInto;

use crate::consts::driver::NDEV;
use crate::consts::fs::{MAXOPBLOCKS, BSIZE};
use crate::consts::fs::{O_RDONLY, O_WRONLY, O_RDWR, O_CREATE, O_TRUNC};
use crate::driver::DEVICES;
use crate::mm::Address;

use super::{ICACHE, LOG, inode::FileStat};
use super::{Inode, InodeType};

mod pipe;

pub use pipe::Pipe;

/// 表示内核中的文件抽象结构，构建在 inode 之上。
///
/// `File` 类型用于统一表示三类文件实体：常规文件（regular file）、设备文件（device）、以及管道（pipe）。
/// 它封装了底层 inode 结构，并通过 `FileInner` 枚举区分实际文件类型。`File` 是用户进程打开文件后在内核态持有的资源，
/// 支持对文件的读写与状态获取等操作，同时在文件关闭时自动释放 inode 或关闭管道端口。
///
/// ### 使用注意：
/// - `File` 使用 `Arc<File>` 管理引用计数，便于在多个线程之间共享；
/// - 文件偏移量通过内部结构中的 `UnsafeCell` 表示，由 inode 锁进行同步；
/// - 打开文件后需调用 `drop` 或将 `Arc` 释放，以触发 inode 或资源的正确回收。
#[derive(Debug)]
pub struct File {
    /// 封装文件内部数据，区分是常规文件、管道还是设备。
    inner: FileInner,

    /// 标志该文件是否支持读取操作。
    readable: bool,

    /// 标志该文件是否支持写入操作。
    writable: bool,
}


unsafe impl Send for File {}
unsafe impl Sync for File {}

impl File {
    /// 打开指定路径的文件，并根据传入的标志位决定是否创建新文件。
    ///
    /// # 功能说明
    /// 该函数提供文件打开功能，支持对常规文件、目录、设备文件进行统一处理。
    /// 若传入 `O_CREATE` 标志，则尝试在路径不存在时创建新文件；否则尝试查找并打开已有文件。
    /// 对于不同类型的 inode，会构造对应的 `FileInner` 实例并初始化可读/可写标志。
    ///
    /// # 流程解释
    /// 1. 启动日志操作（`LOG.begin_op()`），以保障文件系统操作的一致性；
    /// 2. 若指定 `O_CREATE`，尝试使用 `ICACHE.create()` 创建普通文件；
    ///    否则通过 `ICACHE.namei()` 查找现有文件；
    /// 3. 根据 inode 类型判断处理逻辑：
    ///    - 若为 `Directory`，只允许 `O_RDONLY` 打开；
    ///    - 若为 `File`，根据 `O_TRUNC` 标志判断是否截断文件；
    ///    - 若为 `Device`，检查 major 编号合法性并封装为设备文件；
    /// 4. 构造 `File` 结构体并返回其 `Arc` 包装；
    /// 5. 所有路径在出错时需释放 inode 并结束日志操作。
    ///
    /// # 参数
    /// - `path`: 文件路径，使用字节数组形式表示（如 C 字符串）；
    /// - `flags`: 打开标志，支持组合位，如 `O_CREATE`, `O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_TRUNC` 等。
    ///
    /// # 返回值
    /// - `Some(Arc<File>)`：打开成功时，返回封装的文件对象；
    /// - `None`：打开或创建文件失败时返回。
    ///
    /// # 可能的错误
    /// - 路径不存在且未指定 `O_CREATE`；
    /// - 创建文件失败（如目录不存在或权限问题）；
    /// - 尝试以非只读方式打开目录；
    /// - 打开设备文件但 major 编号非法；
    /// - 日志事务未正确结束（通过提前 return 路径确保处理）。
    ///
    /// # 安全性
    /// - 使用 `Arc<File>` 保证跨线程安全共享；
    /// - `offset` 字段通过 `UnsafeCell` 表示内部可变性，由 inode 锁保护并发访问；
    /// - inode 在函数内生命周期受控，出错路径确保正确释放资源与日志。
    pub fn open(path: &[u8], flags: i32) -> Option<Arc<Self>> {
        LOG.begin_op();

        let inode: Inode;
        if flags & O_CREATE > 0 {
            match ICACHE.create(&path, InodeType::File, 0, 0, true) {
                Some(i) => inode = i,
                None => {
                    LOG.end_op();
                    return None
                }
            }
        } else {
            match ICACHE.namei(&path) {
                Some(i) => inode = i,
                None => {
                    LOG.end_op();
                    return None
                }
            }
        }

        let mut idata = inode.lock();
        let inner;
        let readable = (flags & O_WRONLY) == 0;
        let writable = ((flags & O_WRONLY) | (flags & O_RDWR)) > 0;
        match idata.get_itype() {
            InodeType::Empty => panic!("empty inode"),
            InodeType::Directory => {
                if flags != O_RDONLY {
                    drop(idata); drop(inode); LOG.end_op();
                    return None
                }
                drop(idata);
                inner = FileInner::Regular(FileRegular { offset: UnsafeCell::new(0), inode: Some(inode) });
            },
            InodeType::File => {
                if flags & O_TRUNC > 0 {
                    idata.truncate();
                }
                drop(idata);
                inner = FileInner::Regular(FileRegular { offset: UnsafeCell::new(0), inode: Some(inode) });
            },
            InodeType::Device => {
                let (major, _) = idata.get_devnum();
                if major as usize >= NDEV {
                    drop(idata); drop(inode); LOG.end_op();
                    return None
                }
                drop(idata);
                inner = FileInner::Device(FileDevice { major, inode: Some(inode) });
            }
        }

        LOG.end_op();
        Some(Arc::new(File {
            inner,
            readable,
            writable
        }))
    }

    /// 从文件中读取数据到用户空间缓冲区。
    ///
    /// # 功能说明
    /// 该函数从文件中读取至多 `count` 字节的数据，并将其写入用户态地址 `addr` 指向的缓冲区中。
    /// 根据文件类型（普通文件、设备文件或管道）执行不同的读取逻辑，并在读取成功后更新偏移量。
    ///
    /// # 流程解释
    /// 1. 首先检查文件是否具有可读权限（`readable` 标志）；
    /// 2. 根据文件内部类型（`FileInner`）分派读取行为：
    ///    - 若为 `Pipe`，直接调用管道的 `read()` 方法；
    ///    - 若为 `Regular` 文件：
    ///       - 锁住对应 inode；
    ///       - 读取当前偏移量（通过 `UnsafeCell` 提供内部可变性）；
    ///       - 调用 `idata.try_iread()` 读取数据；
    ///       - 更新偏移量并解锁；
    ///    - 若为 `Device` 文件：
    ///       - 查找对应设备驱动的 `read` 函数并调用。
    ///
    /// # 参数
    /// - `addr`: 目标用户缓冲区的起始虚拟地址，读取内容将写入该地址；
    /// - `count`: 尝试读取的最大字节数。
    ///
    /// # 返回值
    /// - `Ok(n)`：成功读取 `n` 字节；
    /// - `Err(())`：读取失败，例如无读权限、设备无效或底层读取错误。
    ///
    /// # 可能的错误
    /// - 文件被标记为不可读（`readable == false`）；
    /// - 对管道/文件进行读取时出现内部错误；
    /// - 对设备文件进行读取时未找到有效驱动；
    /// - `try_iread` 失败（可能因偏移越界或页表映射失败）。
    ///
    /// # 安全性
    /// - 函数本身为不可变借用（`&self`），内部通过 `UnsafeCell` 修改偏移量，仅在持有 inode 锁时进行，确保并发安全；
    /// - 用户空间地址由调用者提供，`try_iread` 负责进行边界检查和页表验证；
    /// - 所有资源使用完毕后立即释放锁，避免死锁或资源泄露。
    pub fn fread(&self, addr: usize, count: u32) -> Result<u32, ()> {
        if !self.readable {
            return Err(())
        }

        match self.inner {
            FileInner::Pipe(ref pipe) => pipe.read(addr, count),
            FileInner::Regular(ref file) => {
                let mut idata = file.inode.as_ref().unwrap().lock();
                let offset = unsafe { &mut *file.offset.get() };
                match idata.try_iread(Address::Virtual(addr), *offset, count.try_into().unwrap()) {
                    Ok(read_count) => {
                        *offset += read_count;
                        drop(idata);
                        Ok(read_count)
                    },
                    Err(()) => Err(())
                }
            },
            FileInner::Device(ref dev) => {
                let dev_read = DEVICES[dev.major as usize].as_ref().ok_or(())?.read;
                dev_read(Address::Virtual(addr), count)
            },
        }
    }

    /// 将用户空间的数据从给定地址写入文件，总共写入不超过 `count` 字节。
    ///
    /// # 功能说明
    /// 该函数负责将用户提供的缓冲区内容写入文件。根据文件类型（普通文件、管道或设备），
    /// 使用不同的方式写入，并在常规文件场景中自动处理偏移更新与日志事务保护。
    ///
    /// # 流程解释
    /// 1. 检查文件是否具有可写权限（`writable`）；
    /// 2. 根据 `FileInner` 类型选择写入路径：
    ///    - `Pipe`：调用管道的 `write()` 实现；
    ///    - `Regular` 文件：
    ///       - 将写入按批次进行分段处理，每批大小为 `((MAXOPBLOCKS-4)/2)*BSIZE` 字节，避免单次事务过大；
    ///       - 每批调用 `LOG.begin_op()` / `end_op()` 包裹文件系统事务；
    ///       - 锁住 inode，调用 `try_iwrite()` 写入当前段；
    ///       - 成功后更新偏移量并移动用户缓冲地址；
    ///    - `Device` 文件：
    ///       - 查找注册的设备驱动中的写入函数并调用。
    ///
    /// # 参数
    /// - `addr`: 用户空间起始地址，写入数据从该地址读取；
    /// - `count`: 要写入的总字节数。
    ///
    /// # 返回值
    /// - `Ok(n)`：实际成功写入的字节数 `n`；
    /// - `Err(())`：写入过程中出现错误。
    ///
    /// # 可能的错误
    /// - 文件未设置为可写（`writable == false`）；
    /// - 管道或设备写入操作失败；
    /// - 对常规文件调用 `try_iwrite()` 失败（如磁盘空间不足、页表错误等）；
    /// - 设备未注册写入函数；
    /// - 写入中途失败（如部分批次失败），返回已成功写入的部分字节。
    ///
    /// # 安全性
    /// - 偏移更新通过 `UnsafeCell` 实现内部可变性，写入前持有 inode 锁确保并发安全；
    /// - 每批写入都封装在日志事务内，保证文件系统的一致性和崩溃恢复能力；
    /// - 用户地址由上层调用者提供，`try_iwrite()` 承担页表检查与物理地址映射验证；
    /// - 写入失败时尽早退出，避免逻辑错误或未定义行为。
    pub fn fwrite(&self, addr: usize, count: u32) -> Result<u32, ()> {
        if !self.writable {
            return Err(())
        }

        match self.inner {
            FileInner::Pipe(ref pipe) => pipe.write(addr, count),
            FileInner::Regular(ref file) => {
                let batch = ((MAXOPBLOCKS-4)/2*BSIZE) as u32;
                let mut addr = Address::Virtual(addr);
                for i in (0..count).step_by(batch as usize) {
                    let write_count = min(batch, count - i);
                    LOG.begin_op();
                    let mut idata = file.inode.as_ref().unwrap().lock();
                    let offset = unsafe { &mut *file.offset.get() };
                    let ret = idata.try_iwrite(addr, *offset, write_count);
                    if let Ok(actual_count) = ret {
                        *offset += actual_count;
                    }
                    drop(idata);
                    LOG.end_op();

                    match ret {
                        Ok(actual_count) => {
                            if actual_count != write_count {
                                return Ok(i+actual_count)
                            }
                        },
                        Err(()) => return Err(()),
                    }
                    addr = addr.offset(write_count as usize);
                }
                Ok(count)
            },
            FileInner::Device(ref dev) => {
                let dev_write = DEVICES[dev.major as usize].as_ref().ok_or(())?.write;
                dev_write(Address::Virtual(addr), count)
            },
        }
    }

    /// 将文件状态信息复制到用户提供的缓冲区中。
    ///
    /// # 功能说明
    /// 该函数用于查询当前文件对应的 inode 元信息，并将其填充到用户提供的 `FileStat` 结构中。
    /// 该信息包括文件类型、大小、设备号等，用于向用户空间暴露文件的基础属性。
    ///
    /// # 流程解释
    /// 1. 判断文件类型（`FileInner`）：
    ///    - 若为 `Pipe` 类型，不支持 fstat 操作，直接返回错误；
    ///    - 否则获取对应的 `inode`；
    /// 2. 获取 `inode` 锁，确保元数据访问的并发安全；
    /// 3. 调用 `istat()` 方法将 inode 内部状态写入 `stat`；
    /// 4. 解锁并返回成功。
    ///
    /// # 参数
    /// - `stat`: 指向 `FileStat` 结构体的可变引用，用于接收查询到的文件状态信息。
    ///
    /// # 返回值
    /// - `Ok(())`：成功将 inode 信息写入到 `stat`；
    /// - `Err(())`：当前文件为管道类型，不支持状态查询。
    ///
    /// # 可能的错误
    /// - 管道文件不支持状态查询，调用该函数时会立即返回错误；
    /// - 若 `inode` 字段为 `None`，`.unwrap()` 会引发 panic（当前代码逻辑中认为这种情况不会发生，但在未来修改中应警惕）。
    ///
    /// # 安全性
    /// - `inode` 的锁机制确保了 `istat` 操作过程中的并发安全；
    /// - 使用 `.unwrap()` 解包 `Option<Inode>`，假设 `Regular` 和 `Device` 类型的 `File` 必定包含有效的 `inode`；
    ///   若此前已被 `drop` 释放则可能触发未定义行为，因此要求在 `drop` 调用前完成所有状态访问；
    /// - `stat` 指针必须来源于内核或受控用户空间，确保写入不会越界或违反内存访问规则。
    pub fn fstat(&self, stat: &mut FileStat) -> Result<(), ()> {
        let inode: &Inode;
        match self.inner {
            FileInner::Pipe(_) => return Err(()),
            FileInner::Regular(ref file) => inode = file.inode.as_ref().unwrap(),
            FileInner::Device(ref dev) => inode = dev.inode.as_ref().unwrap(),
        }
        let idata = inode.lock();
        idata.istat(stat);
        Ok(())
    }
}

impl Drop for File {
    /// 关闭文件并释放相关资源。
    ///
    /// # 功能说明
    /// 此函数为 `File` 结构体的析构实现（Drop trait），用于在文件引用计数归零时自动释放资源。
    /// 根据文件类型（管道、常规文件、设备）执行相应的关闭逻辑，确保 inode 正确释放或管道端正确关闭。
    ///
    /// # 流程解释
    /// 1. 根据 `FileInner` 的具体变体进行匹配：
    ///    - 若为 `Pipe` 类型，调用其 `close()` 方法，并传入当前 `File` 是否为写端；
    ///    - 若为 `Regular` 或 `Device` 类型，执行以下步骤：
    ///      - 开启日志事务（`LOG.begin_op()`）；
    ///      - 将其中的 inode 设置为 `None`，释放其引用；
    ///      - 结束日志事务（`LOG.end_op()`）。
    ///
    /// # 参数
    /// 无参数。该函数为析构器，由 Rust 在 `File` 被销毁时自动调用。
    ///
    /// # 返回值
    /// 无返回值。
    ///
    /// # 可能的错误
    /// - 本函数本身不返回错误；但如若 `inode.take()` 前已经非法释放或未按约定初始化，可能引发逻辑错误或 panic；
    /// - 管道关闭逻辑依赖于 `Pipe::close()` 的内部实现，若其处理不当可能出现资源未完全释放。
    ///
    /// # 安全性
    /// - 对 `inode` 的释放使用 `Option::take()`，确保只释放一次，防止双重释放；
    /// - `LOG.begin_op()` / `end_op()` 包裹对 inode 的释放，保障文件系统状态一致性；
    /// - 管道关闭操作可能涉及跨线程通信，需确保 `close()` 内部实现具备并发安全保障；
    /// - 函数不应在未完成文件操作前手动调用，应由 Rust 生命周期自动触发。
    fn drop(&mut self) {
        match self.inner {
            FileInner::Pipe(ref pipe) => pipe.close(self.writable),
            FileInner::Regular(ref mut file) => {
                LOG.begin_op();
                drop(file.inode.take());
                LOG.end_op();
            },
            FileInner::Device(ref mut dev) => {
                LOG.begin_op();
                drop(dev.inode.take());
                LOG.end_op();
            },
        }
    }
}

/// 表示文件内部的具体实现类型，用于区分文件的实际存储或通信方式。
///
/// 该枚举结构用于 `File` 抽象内部，根据不同文件类型（管道、普通文件、设备）
/// 封装对应的数据结构，从而实现统一的文件接口（如读写、关闭、状态查询）
/// 而无需暴露具体实现细节。每个变体都携带相应的资源句柄或元数据。
#[derive(Debug)]
enum FileInner {
    /// 管道文件，表示进程间通信通道，封装为引用计数的 `Pipe` 实例。
    /// 使用 `Arc` 保证跨线程共享与安全释放。
    Pipe(Arc<Pipe>),

    /// 常规文件，包含偏移量与 inode，用于磁盘文件的读写。
    Regular(FileRegular),

    /// 设备文件，包含主设备号与 inode，用于通过驱动进行 I/O。
    Device(FileDevice),
}


/// 表示普通文件的内部状态结构，封装在 `FileInner::Regular` 变体中。
///
/// 用于管理磁盘上的常规文件（regular file），包含当前文件的偏移位置和 inode 引用。
/// 文件偏移用于顺序读写操作，inode 提供底层元数据与数据访问接口。
/// 该结构承载对常规文件的状态管理职责。
#[derive(Debug)]
struct FileRegular {
    /// 当前文件偏移量，表示下一次读写操作的起始位置。
    ///
    /// 该字段通过 `UnsafeCell` 提供内部可变性，
    /// 实际使用中由 inode 上的锁（`idata`）保护，确保并发访问时的一致性与内存安全。
    offset: UnsafeCell<u32>,

    /// 指向该文件对应的 inode 对象，用于文件的元数据与数据访问。
    ///
    /// 使用 `Option<Inode>` 表示可释放性，在文件关闭（drop）时会被设置为 `None`。
    inode: Option<Inode>,
}


/// 表示设备文件的内部状态结构，封装在 `FileInner::Device` 变体中。
///
/// 该结构用于管理字符设备文件，允许通过设备号与驱动接口进行读写操作。
/// 设备文件并不实际存储数据，而是通过设备号与内核中注册的设备驱动进行通信。
/// 该结构用于抽象和封装对设备节点的访问。
#[derive(Debug)]
struct FileDevice {
    /// 主设备号（major device number），用于在设备表中索引对应的设备驱动。
    ///
    /// 在 xv6 中，每种设备（如控制台、磁盘等）都有唯一的主设备号，
    /// 通过该编号调用统一的设备操作接口（如 `read` / `write`）。
    major: u16,

    /// 指向设备对应的 inode 对象。
    ///
    /// 尽管设备文件不依赖 inode 进行实际数据存储，但依然使用 inode 记录其元信息，
    /// 并在文件关闭时通过 `Option::take()` 释放。
    inode: Option<Inode>,
}
