//! buffer cache layer

use array_macro::array;

use core::ptr;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{Ordering, AtomicBool};

use crate::sleeplock::{SleepLock, SleepLockGuard};
use crate::spinlock::SpinLock;
use crate::driver::virtio_disk::DISK;
use crate::consts::fs::{NBUF, BSIZE};

pub static BCACHE: Bcache = Bcache::new();

/// 全局缓冲区缓存（Buffer Cache）结构体，用于块设备的读写缓存。
///
/// `Bcache` 提供了一个固定大小的内存缓冲区池，用于缓存磁盘块数据，
/// 以减少重复的磁盘访问并提升 I/O 性能。它结合 LRU（最近最少使用）替换策略
/// 维护块缓冲的使用顺序，并通过自旋锁与睡眠锁机制实现线程安全的数据访问。
///
/// 该结构通常在内核初始化阶段被构造，并贯穿操作系统运行期间，
/// 是文件系统与块设备驱动之间的关键缓冲层。
pub struct Bcache {
    /// 控制 LRU 缓存元信息的自旋锁。
    ///
    /// 该字段保护 `BufLru`，后者用于维护所有缓冲块的 LRU 链表结构、
    /// 引用计数、块号与设备号等元数据。通过该锁可实现并发环境下安全的
    /// 块定位与替换操作。
    ctrl: SpinLock<BufLru>,

    /// 缓冲块数组，长度为固定值 `NBUF`。
    ///
    /// 每个缓冲块包含块数据和一个睡眠锁（`SleepLock`），
    /// 以支持对缓冲区数据的细粒度同步访问。缓存内容由 `ctrl` 控制字段协调管理。
    bufs: [BufInner; NBUF],
}

impl Bcache {
    const fn new() -> Self {
        Self {
            ctrl: SpinLock::new(BufLru::new(), "BufLru"),
            bufs: array![_ => BufInner::new(); NBUF],
        }
    }

    /// 初始化全局缓冲区缓存 `Bcache`。
    ///
    /// # 功能说明
    /// 本函数用于在内核启动阶段初始化缓冲区缓存控制结构，特别是构建 LRU 缓存链表的结构，
    /// 包括设置链表的头尾指针、节点之间的前后指针关系，以及每个缓存控制项的索引值。
    /// 该函数应仅在系统启动时调用一次，后续不可重复初始化。
    ///
    /// # 流程解释
    /// - 获取 `ctrl` 的自旋锁，确保初始化期间的独占访问；
    /// - 设置 `BufLru` 中的 `head` 和 `tail` 指针，分别指向第一个和最后一个缓冲控制块；
    /// - 初始化 LRU 链表中每个节点的 `prev` 和 `next` 指针，形成双向链表结构；
    /// - 遍历所有 `BufCtrl` 项，设置其 `index` 字段，使其记录自身在线性数组中的位置。
    ///
    /// # 参数
    /// - `&self`：`Bcache` 的共享引用，表示对全局缓冲区缓存的访问。
    ///
    /// # 返回值
    /// - 无返回值。该函数仅执行初始化逻辑。
    ///
    /// # 可能的错误
    /// - 如果该函数被多次调用，可能引发链表结构混乱或数据不一致；
    /// - 当前实现未对重复调用进行保护，调用方需保证只执行一次。
    ///
    /// # 安全性
    /// - 使用 `SpinLock` 保护对 `BufLru` 的修改，确保在多核或并发环境中初始化过程的原子性与互斥性；
    /// - 使用原始指针构造链表，但仅在初始化阶段使用，逻辑上是安全的，后续操作通过受控路径访问。
    pub fn binit(&self) {
        let mut ctrl = self.ctrl.lock();
        let len = ctrl.inner.len();

        // init the head and tail of the lru list
        ctrl.head = &mut ctrl.inner[0];
        ctrl.tail = &mut ctrl.inner[len-1];

        // init prev and next field
        ctrl.inner[0].prev = ptr::null_mut();
        ctrl.inner[0].next = &mut ctrl.inner[1];
        ctrl.inner[len-1].prev = &mut ctrl.inner[len-2];
        ctrl.inner[len-1].next = ptr::null_mut();
        for i in 1..(len-1) {
            ctrl.inner[i].prev = &mut ctrl.inner[i-1];
            ctrl.inner[i].next = &mut ctrl.inner[i+1];
        }
        
        // init index
        ctrl.inner.iter_mut()
            .enumerate()
            .for_each(|(i, b)| b.index = i);
    }

    /// 获取指定设备与块号对应的缓冲块引用。
    ///
    /// # 功能说明
    /// `bget` 是缓冲区缓存系统的底层接口，用于查找是否已缓存给定的 `(dev, blockno)` 对应的块。
    /// 若缓存命中，则返回已存在的缓冲块；否则尝试回收一个未被引用的块，并将其分配给新请求。
    /// 该函数不涉及实际磁盘读写，调用者需通过 `valid` 字段判断是否需要从磁盘加载数据。
    ///
    /// # 流程解释
    /// - 首先通过自旋锁锁住 `BufLru` 控制结构，保证操作的原子性；
    /// - 调用 `find_cached` 查找是否已有缓存块命中；
    ///   - 若命中，则增加引用计数，并返回对应的 `Buf` 对象；
    ///   - 若未命中，尝试调用 `recycle` 从 LRU 尾部回收一个未被引用的缓存块；
    ///     - 若成功回收，则重置其 `valid` 状态，更新其 `(dev, blockno)`，并返回新的 `Buf`；
    ///     - 若无法回收（说明所有缓冲块都在被使用），触发 panic。
    ///
    /// # 参数
    /// - `dev`: 块所属的设备编号。
    /// - `blockno`: 块在设备中的逻辑块号。
    ///
    /// # 返回值
    /// - 返回一个 `Buf` 对象，表示当前已分配用于该 `(dev, blockno)` 对应的缓冲块，
    ///   该对象内部持有一个 `SleepLockGuard`，用于对缓冲块数据的独占访问。
    ///
    /// # 可能的错误
    /// - 当所有缓冲块都处于被引用状态时，无法执行替换，会触发 panic（`"no usable buffer"`）。
    ///
    /// # 安全性
    /// - 整个函数通过 `SpinLock` 保证 `BufLru` 的访问安全；
    /// - 引用计数通过裸指针操作修改（`rc_ptr`），但其生命周期受控于 `Buf` 的 `Drop` 实现；
    /// - 使用 `Relaxed` 顺序操作 `valid` 标志位，仅适用于初始化阶段，调用者需保证正确同步。
    fn bget(&self, dev: u32, blockno: u32) -> Buf<'_> {
        let mut ctrl = self.ctrl.lock();

        // find cached block
        match ctrl.find_cached(dev, blockno) {
            Some((index, rc_ptr)) => {
                // found
                drop(ctrl);
                Buf {
                    index,
                    dev,
                    blockno,
                    rc_ptr,
                    data: Some(self.bufs[index].data.lock())
                }
            }
            None => {
                // not cached
                // recycle the least recently used (LRU) unused buffer
                match ctrl.recycle(dev, blockno) {
                    Some((index, rc_ptr)) => {
                        self.bufs[index].valid.store(false, Ordering::Relaxed);
                        drop(ctrl);
                        return Buf {
                            index,
                            dev,
                            blockno,
                            rc_ptr,
                            data: Some(self.bufs[index].data.lock()),
                        }
                    }
                    None => panic!("no usable buffer")
                }
            }
        }
    }

    /// 从缓冲区缓存中读取指定设备与块号对应的数据。
    ///
    /// # 功能说明
    /// 该函数是对外提供的读取接口，用于从缓存中获取给定 `(dev, blockno)` 对应的缓冲块。
    /// 若缓冲块未被标记为有效（即未曾从磁盘加载），则会自动触发一次从磁盘读取操作。
    ///
    /// # 流程解释
    /// - 调用 `bget` 获取目标块的缓冲结构，若命中缓存则直接返回；
    /// - 若该缓冲块的 `valid` 标志为 false，表示当前块数据尚未从磁盘加载；
    ///   - 调用底层磁盘驱动 `DISK.rw` 执行一次读取；
    ///   - 读取完成后设置该块的 `valid` 标志为 true；
    /// - 返回已准备就绪的缓冲块 `Buf` 对象。
    ///
    /// # 参数
    /// - `dev`: 设备号，标识请求的块所属的块设备；
    /// - `blockno`: 块号，标识请求的块在设备上的逻辑位置。
    ///
    /// # 返回值
    /// - 返回一个 `Buf` 对象，表示包含指定块数据的缓冲区，内部持有锁保护的数据访问权。
    ///
    /// # 可能的错误
    /// - 若 `bget` 无法获取可用缓冲块（所有块都处于使用中），将触发 panic；
    /// - 若底层磁盘驱动在读取过程中发生错误，当前实现未提供显式错误处理路径，可能导致系统行为未定义。
    ///
    /// # 安全性
    /// - 缓冲块的访问受 `SpinLock` 和 `SleepLock` 多层保护，确保并发访问安全；
    /// - 对 `valid` 标志的操作使用 `Relaxed` 内存序，调用者需确保在合理同步场景下使用；
    /// - `Buf` 对象的生命周期由 Rust 所保障，释放时自动调用 `Drop` 实现更新 LRU 状态。
    pub fn bread<'a>(&'a self, dev: u32, blockno: u32) -> Buf<'a> {
        let mut b = self.bget(dev, blockno);
        if !self.bufs[b.index].valid.load(Ordering::Relaxed) {
            DISK.rw(&mut b, false);
            self.bufs[b.index].valid.store(true, Ordering::Relaxed);
        }
        b
    }

    /// 释放缓冲块的引用，将其移动到最近使用的位置（LRU 首部）如果不再被引用。
    ///
    /// # 功能说明
    /// 该函数用于在 `Buf` 被释放（即生命周期结束）时通知缓冲区管理器更新其 LRU 状态。
    /// 如果该缓冲块的引用计数已经归零（即没有其他活跃用户），则将其移动至 LRU 链表的头部，
    /// 表示它是最近最少使用的，可以被后续替换。
    fn brelse(&self, index: usize) {
        self.ctrl.lock().move_if_no_ref(index);
    }
}

/// 缓冲块数据的包装结构，表示一个已分配的磁盘块缓存实体。
///
/// `Buf` 结构代表一个特定 `(dev, blockno)` 的缓冲区块，
/// 持有对其数据的独占访问权限（由 `SleepLockGuard` 保护），
/// 并在生命周期结束时自动调用 `Drop`，更新 LRU 状态。
/// 
/// 该结构在使用者访问块设备读写时由 `bread` / `bget` 创建，
/// 保证在作用域内安全使用，同时借助裸指针实现对引用计数的管理。
pub struct Buf<'a> {
    /// 缓冲块在全局缓冲数组中的索引位置。
    ///
    /// 用于在 `BCACHE.bufs` 中快速定位对应的 `BufInner`。
    index: usize,

    /// 缓冲块对应的设备编号。
    ///
    /// 标识该缓冲块属于哪个块设备（如虚拟磁盘）。
    dev: u32,

    /// 缓冲块在设备中的逻辑块号。
    ///
    /// 每个缓冲块唯一由 `(dev, blockno)` 对组成。
    blockno: u32,

    /// 指向该缓冲块引用计数的裸指针。
    ///
    /// 指向 `BufCtrl` 中 `refcnt` 字段的指针，
    /// 用于手动管理该缓冲块的引用计数（`pin`/`unpin`）。
    /// 由 `bget` 或 `recycle` 函数初始化，使用时需确保生命周期有效。
    rc_ptr: *mut usize,

    /// 缓冲数据的睡眠锁保护访问器。
    ///
    /// 在 `Buf` 生命周期内保证始终为 `Some`，
    /// 提前释放该字段可以实现先释放锁再触发 `Drop` 的行为。
    /// 使用 `SleepLockGuard` 进行数据访问的同步控制。
    data: Option<SleepLockGuard<'a, BufData>>,
}


impl<'a> Buf<'a> {
    pub fn read_blockno(&self) -> u32 {
        self.blockno
    }

    pub fn bwrite(&mut self) {
        DISK.rw(self, true);
    }

    /// Gives out a raw const pointer at the buf data. 
    pub fn raw_data(&self) -> *const BufData {
        let guard = self.data.as_ref().unwrap();
        guard.deref()
    }

    /// Gives out a raw mut pointer at the buf data. 
    pub fn raw_data_mut(&mut self) -> *mut BufData {
        let guard = self.data.as_mut().unwrap();
        guard.deref_mut()
    }

    /// 将当前缓冲块的引用计数加一，表示“钉住”该块，防止其被回收。
    ///
    /// # 功能说明
    /// 在缓冲块被访问过程中，如果希望确保该块在某段时间内不被 LRU 回收机制替换，
    /// 应调用 `pin` 将其引用计数加一。该操作常用于块的临时占用，需与 `unpin` 配对使用。
    pub unsafe fn pin(&self) {
        let rc = *self.rc_ptr;
        *self.rc_ptr = rc + 1;
    }

    /// 将当前缓冲块的引用计数减一，表示释放“钉住”状态。
    ///
    /// # 功能说明
    /// `unpin` 是与 `pin` 对应的操作，用于在缓冲块使用完毕后释放其占用，
    /// 从而允许缓存系统在必要时将该缓冲块替换或回收。必须与 `pin` 配对调用，
    /// 否则可能引发 panic 或缓存状态不一致。
    pub unsafe fn unpin(&self) {
        let rc = *self.rc_ptr;
        if rc <= 1 {
            panic!("buf unpin not match");
        }
        *self.rc_ptr = rc - 1;
    }
}

impl<'a> Drop for Buf<'a> {
    fn drop(&mut self) {
        drop(self.data.take());
        BCACHE.brelse(self.index);        
    }
}

/// 缓冲区缓存的 LRU（最近最少使用）链表控制结构。
///
/// `BufLru` 用于管理所有缓冲块的元信息，并通过双向链表实现 LRU 替换策略。
/// 它负责追踪每个缓冲块的使用状态（通过引用计数）以及在链表中的位置，
/// 以支持 `bget`、`recycle` 和 `brelse` 等缓存分配与回收操作。
/// 
/// 该结构在整个系统运行期间保持常驻，由 `SpinLock` 保护其并发访问。
struct BufLru {
    /// 缓冲控制块数组，长度固定为 `NBUF`。
    ///
    /// 每个元素对应一个缓存块的控制信息（`BufCtrl`），
    /// 包含块号、设备号、引用计数以及 LRU 链表中的前后指针。
    inner: [BufCtrl; NBUF],

    /// 指向当前 LRU 链表的头节点（最少刚使用的块）。
    ///
    /// 所有新获取或释放引用为 0 的缓冲块都会尝试被移到链表头部，
    /// 优先保留。若为空，则表示链表尚未初始化。
    head: *mut BufCtrl,

    /// 指向当前 LRU 链表的尾节点（最久未使用的块）。
    ///
    /// 回收操作通常从尾部开始查找未被引用的块作为替换目标；
    /// 若为空，则表示链表尚未初始化。
    tail: *mut BufCtrl,
}


/// Raw pointers are automatically thread-unsafe.
/// See doc https://doc.rust-lang.org/nomicon/send-and-sync.html.
unsafe impl Send for BufLru {}

impl BufLru {
    const fn new() -> Self {
        Self {
            inner: array![_ => BufCtrl::new(); NBUF],
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
        }
    }

    /// 查找是否缓存中已存在指定设备和块号的缓冲块。
    ///
    /// # 功能说明
    /// 该函数在 LRU 缓存链表中从头部开始遍历，查找是否存在与 `(dev, blockno)` 匹配的缓冲块。
    /// 若命中，则将该缓冲块的引用计数加一，并返回其索引及引用计数指针；
    /// 若未命中，则返回 `None`。
    ///
    /// # 流程解释
    /// - 从 `head` 开始顺序遍历 LRU 链表；
    /// - 每次通过裸指针访问链表节点，判断其 `(dev, blockno)` 是否匹配；
    /// - 若找到匹配项：
    ///   - 将对应缓冲块的引用计数加一；
    ///   - 返回该缓冲块在缓存数组中的索引及其引用计数指针；
    /// - 若未找到，则返回 `None`。
    ///
    /// # 参数
    /// - `dev`: 缓冲块所属设备编号；
    /// - `blockno`: 缓冲块在设备中的逻辑块号。
    ///
    /// # 返回值
    /// - `Some((index, rc_ptr))`：命中缓存时，返回缓存块在数组中的索引以及其引用计数的裸指针；
    /// - `None`：未命中缓存。
    ///
    /// # 可能的错误
    /// - 依赖 `head` 初始化正确，若链表未正确构建，可能导致空指针访问或逻辑错误；
    /// - 对 `refcnt` 的加法操作未加锁，假设函数调用者已在外部持有互斥锁；
    /// - 若缓存中存在重复条目（不应发生），可能导致重复引用计数。
    ///
    /// # 安全性
    /// - 函数使用 `unsafe` 解引用裸指针，要求调用前已确保链表结构有效；
    /// - 函数本身不会引发未定义行为，但需要由外部同步机制（如 `SpinLock`）确保线程安全；
    /// - 返回的 `*mut usize` 指针需由调用者保证在使用期间不被悬挂或重复释放。
    fn find_cached(&mut self, dev: u32, blockno: u32) -> Option<(usize, *mut usize)> {
        let mut b = self.head;
        while !b.is_null() {
            let bref = unsafe { b.as_mut().unwrap() };
            if bref.dev == dev && bref.blockno == blockno {
                bref.refcnt += 1;
                return Some((bref.index, &mut bref.refcnt));
            }
            b = bref.next;
        }
        None
    }

    /// 从 LRU 链表尾部回收一个未被使用（引用计数为 0）的缓冲块。
    ///
    /// # 功能说明
    /// 该函数用于在缓存未命中时，从缓存池中寻找一个可用的空闲缓冲块进行复用。
    /// 搜索方向从 LRU 链表的尾部开始，即优先替换“最久未使用”的缓存项。
    /// 一旦找到未被引用的块，会将其设备号和块号更新为新的目标，并增加其引用计数。
    ///
    /// # 流程解释
    /// - 从 `tail` 开始向前遍历 LRU 链表；
    /// - 对每个缓存块检查其引用计数是否为 0（表示空闲）；
    /// - 一旦找到空闲块：
    ///   - 更新其 `dev` 和 `blockno` 为新的目标；
    ///   - 将引用计数设为 1，表示被当前请求占用；
    ///   - 返回其在缓存数组中的索引和引用计数的裸指针；
    /// - 若遍历完整个链表都未找到空闲块，返回 `None`。
    ///
    /// # 参数
    /// - `dev`: 新缓冲块要绑定的设备编号；
    /// - `blockno`: 新缓冲块要绑定的逻辑块号。
    ///
    /// # 返回值
    /// - `Some((index, rc_ptr))`：若成功找到可回收块，返回其在缓存数组中的索引及其引用计数的指针；
    /// - `None`：若当前无空闲缓冲块可用。
    ///
    /// # 可能的错误
    /// - 如果所有缓存块均处于使用中（`refcnt > 0`），则无法完成回收，返回 `None`；
    /// - 若链表结构被破坏（如指针错误或未初始化），可能导致 `unsafe` 解引用失败；
    /// - 当前实现不会自动驱逐脏页或写回内容，仅简单进行占用替换，可能导致数据丢失（教学环境中受控）。
    ///
    /// # 安全性
    /// - 使用裸指针进行链表遍历与节点访问，调用前必须确保 LRU 链表结构有效；
    /// - 必须由外层 `SpinLock` 保证对 `BufLru` 的互斥访问；
    /// - 修改返回缓冲块的元信息（`dev`、`blockno`、`refcnt`）必须确保该缓冲块当前未被任何线程访问；
    /// - 返回的裸指针必须由调用者妥善管理，确保生命周期有效且不会悬挂或越界。
    fn recycle(&mut self, dev: u32, blockno: u32) -> Option<(usize, *mut usize)> {
        let mut b = self.tail;
        while !b.is_null() {
            let bref = unsafe { b.as_mut().unwrap() };
            if bref.refcnt == 0 {
                bref.dev = dev;
                bref.blockno = blockno;
                bref.refcnt += 1;
                return Some((bref.index, &mut bref.refcnt));
            }
            b = bref.prev;
        }
        None
    }

    /// 若缓冲块不再被引用，则将其移至 LRU 链表头部。
    ///
    /// # 功能说明
    /// 本函数用于在缓冲块引用计数归零后，将该块视为“最近使用”项插入 LRU 链表头部。
    /// 这样可延迟其被回收，增加后续命中缓存的机会。若引用计数仍大于零或该块已在链表头部，
    /// 则不进行任何操作。
    ///
    /// # 流程解释
    /// - 获取缓存控制块 `BufCtrl` 并将其引用计数减一；
    /// - 检查是否满足以下条件：
    ///   - 当前引用计数变为 0；
    ///   - 缓冲块不在 LRU 链表头部；
    /// - 若满足：
    ///   - 若该块正处于尾部，更新尾指针 `tail` 为其前一个节点；
    ///   - 将当前节点从原链表位置摘除（更新前后节点指针）；
    ///   - 将其插入到链表头部，并更新 `head` 指针；
    /// - 否则直接返回。
    ///
    /// # 参数
    /// - `index`: 缓冲块在全局缓存数组中的索引位置。
    ///
    /// # 返回值
    /// - 无返回值。函数通过副作用更新链表结构与引用计数。
    ///
    /// # 可能的错误
    /// - 如果引用计数在调用前已经为 0，再次调用将导致引用计数为负，造成逻辑错误；
    /// - 若链表结构已被破坏，裸指针操作可能导致未定义行为；
    /// - 若未正确持有对 `BufLru` 的锁，会出现竞态条件，破坏链表一致性。
    ///
    /// # 安全性
    /// - 使用了 `unsafe` 操作对裸指针解引用并修改链表结构，调用者必须确保：
    ///   - 当前线程已独占访问 `BufLru`（通常由外部 `SpinLock` 保证）；
    ///   - 所有链表节点结构已初始化且未被其他线程修改；
    /// - 本函数假设传入的 `index` 在 `inner` 数组范围内，且对应的缓冲块在有效状态；
    /// - 如果这些条件被破坏，将可能导致内存悬挂或越界访问。
    fn move_if_no_ref(&mut self, index: usize) {
        let b = &mut self.inner[index];
        b.refcnt -= 1;
        if b.refcnt == 0 && !ptr::eq(self.head, b) {
            // forward the tail if b is at the tail
            // b may be the only entry in the lru list
            if ptr::eq(self.tail, b) && !b.prev.is_null() {
                self.tail = b.prev;
            }
            
            // detach b
            unsafe {
                b.next.as_mut().map(|b_next| b_next.prev = b.prev);
                b.prev.as_mut().map(|b_prev| b_prev.next = b.next);
            }

            // attach b
            b.prev = ptr::null_mut();
            b.next = self.head;
            unsafe {
                self.head.as_mut().map(|old_head| old_head.prev = b);
            }
            self.head = b;
        }
    }
}

/// 缓冲块控制结构，用于记录缓冲区的元信息并构建 LRU 链表。
///
/// `BufCtrl` 并不包含具体的块数据，而是负责维护每个缓冲块的控制信息，
/// 包括其所属设备、块号、引用计数、LRU 链表前后指针以及在全局缓冲区数组中的位置索引。
/// 它是 `BufLru` 实现 LRU 缓存替换策略的核心组成部分。
struct BufCtrl {
    /// 缓冲块所属的设备号。
    ///
    /// 与 `blockno` 共同标识该缓冲块所映射的磁盘位置。
    dev: u32,

    /// 缓冲块在设备中的逻辑块号。
    ///
    /// 与 `dev` 一起构成缓存块的唯一标识。
    blockno: u32,

    /// 指向前一个缓冲块控制块的裸指针。
    ///
    /// 用于在 `BufLru` 中构建 LRU 双向链表，表示链表中前驱节点；
    /// 若为链表头节点，则为 `null_mut()`。
    prev: *mut BufCtrl,

    /// 指向下一个缓冲块控制块的裸指针。
    ///
    /// 用于在 `BufLru` 中构建 LRU 双向链表，表示链表中后继节点；
    /// 若为链表尾节点，则为 `null_mut()`。
    next: *mut BufCtrl,

    /// 当前缓冲块的引用计数。
    ///
    /// 表示该块当前正在被多少个 `Buf` 实例使用；
    /// 为 0 时表示未被使用，可被 `recycle` 回收；
    /// 大于 0 表示该块处于活跃使用状态，不能被替换。
    refcnt: usize,

    /// 当前控制块在全局缓冲数组 `BCACHE.bufs` 中的索引位置。
    ///
    /// 用于快速定位对应的缓冲块数据（`BufInner`）。
    index: usize,
}


impl BufCtrl {
    const fn new() -> Self {
        Self {
            dev: 0,
            blockno: 0,
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
            refcnt: 0,
            index: 0,
        }
    }
}

/// 缓冲块的数据部分，包含实际的磁盘块内容及其有效性标志。
///
/// `BufInner` 是缓冲区系统中与 `BufCtrl` 配对的结构，
/// 用于存储每个块的数据内容及其有效性状态。
/// 它由 `BCACHE.bufs` 数组统一管理，每项与 `BufCtrl` 的索引一一对应。
/// 数据访问通过 `SleepLock` 保护，以支持细粒度的同步，
/// 有效位则由 `AtomicBool` 表示，并在访问期间由 `SpinLock` 或 `SleepLock` 保护。
struct BufInner {
    /// 标志该缓冲块的数据是否有效。
    ///
    /// - `true`: 表示当前缓冲块已包含有效的数据，可直接使用；
    /// - `false`: 表示需要通过磁盘读取填充数据；
    ///
    /// 该字段由 `bget` 设置，在 `bread` 中使用，在持有 bcache 自旋锁或 data 睡眠锁时才允许访问。
    valid: AtomicBool,

    /// 缓冲块的实际数据，受睡眠锁保护。
    ///
    /// 数据类型为 `BufData`，由 `SleepLock` 包裹，确保一次只有一个线程可访问该缓冲块的数据。
    /// 在调用 `bread` 或 `bwrite` 等操作时自动加锁访问。
    data: SleepLock<BufData>,
}


impl BufInner {
    const fn new() -> Self {
        Self {
            valid: AtomicBool::new(false),
            data: SleepLock::new(BufData::new(), "BufData"),
        }
    }
}

/// Alignment of BufData should suffice for other structs
/// that might converts from this struct.
#[repr(C, align(8))]
pub struct BufData([u8; BSIZE]);

impl  BufData {
    const fn new() -> Self {
        Self([0; BSIZE])
    }
}
