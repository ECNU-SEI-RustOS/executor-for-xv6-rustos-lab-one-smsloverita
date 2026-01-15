//! The kernel heap allocator
//!
//! reference: https://pdos.csail.mit.edu/6.828/2019/lec/malloc.c

use bit_field::BitField;

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self};
use core::mem::{MaybeUninit, size_of};
use core::cmp;

use crate::consts::{PGSIZE, LEAF_SIZE, PHYSTOP};
use crate::spinlock::SpinLock;
use super::list::List;

/// 全局内核堆分配器。
///
/// 该静态变量实现了 Rust 的 [`GlobalAlloc`] 接口，
/// 并通过 `#[global_allocator]` 标记为全局分配器，
/// 用于为内核中的所有堆分配请求提供支持。
///
/// 它包装了一个基于伙伴系统（buddy system）的堆分配器 [`BuddySystem`]，
/// 可在系统初始化早期通过 [`KernelHeap::kinit`] 完成堆空间的初始化，
/// 从而管理内核可用的物理内存区间。
///
/// # 安全性
///
/// 在调用 `kinit()` 初始化之前，不应进行任何堆分配操作。
#[global_allocator]
pub static KERNEL_HEAP: KernelHeap = KernelHeap::uninit();

#[alloc_error_handler]
fn foo(layout: Layout) -> ! {
    panic!("alloc error: {:?}", layout)
}

/// 内核堆分配器封装结构。
///
/// `KernelHeap` 是整个内核的堆内存分配器核心类型，
/// 它通过内部封装一个加锁的 [`BuddySystem`]，
/// 提供线程安全的堆内存分配与回收机制。
///
/// # 初始化
///
/// 在系统启动早期，应调用 [`KernelHeap::kinit`] 来初始化堆管理区间，
/// 否则任何堆分配行为都将引发错误。
pub struct KernelHeap(SpinLock<BuddySystem>);

impl KernelHeap {
    const fn uninit() -> Self {
        Self(SpinLock::new(BuddySystem::uninit(), "kernel heap"))
    }

    /// 初始化内核堆分配器。
    ///
    /// 在内核启动早期调用此函数，用于初始化整个内核堆的可用物理内存区域，
    /// 其作用是将从链接脚本中 `_end` 符号（表示内核镜像末尾）
    /// 到 `PHYSTOP` 之间的物理内存设置为可管理的堆空间。
    ///
    /// # 功能说明
    ///
    /// - 获取内核镜像结束地址 `_end` 作为起点，
    ///   将区间 `[end, PHYSTOP)` 注册到内部伙伴系统中进行内存管理；
    /// - 调用内部 `init()` 方法完成堆空间的初始化；
    /// - 会打印可用内存区间和初始化完成提示信息。
    ///
    /// # 参数
    ///
    /// - `&self`：对当前 `KernelHeap` 分配器的不可变引用。
    ///
    /// # 返回值
    ///
    /// - 无返回值，函数执行完成后 `KernelHeap` 将处于可分配状态。
    /// 
    /// # 安全性
    ///
    /// - 本函数为 `unsafe`，因为直接从裸指针读取 `_end` 符号，
    ///   并假设其值正确无误；
    /// - 使用者必须确保仅调用一次，并在其他堆分配操作之前调用；
    /// - 不应在初始化前使用任何需要堆内存的结构（如 `Box`、`Vec`）
    pub unsafe fn kinit(&self) {
        extern "C" {
            fn end();
        }
        let end = end as usize;
        println!("KernelHeap: available physical memory [{:#x}, {:#x})", end, usize::from(PHYSTOP));
        self.init(end, usize::from(PHYSTOP));
        println!("KernelHeap: init memory done");
    }

    /// 初始化内核堆分配器的实现函数。
    ///
    /// 在内核启动过程中调用此函数，用于初始化伙伴系统分配器，
    /// 将 `[start, end)` 范围内的物理内存注册为可管理的堆空间，
    /// 并建立用于内存分配的元数据结构（如分配位图、分裂标记等）。
    ///
    /// # 功能说明
    ///
    /// - 加锁访问内部 [`BuddySystem`]，并调用其 `init()` 方法；
    /// - 设置堆起始地址、对齐边界，并初始化所有管理元信息；
    /// 
    /// # 参数
    ///
    /// - `start`: 要加入堆管理的起始物理地址，通常为内核镜像结束地址；
    /// - `end`: 要加入堆管理的结束物理地址，通常为物理内存上限（如 `PHYSTOP`）；
    ///
    /// # 返回值
    ///
    /// - 无返回值。函数执行成功后，内核堆分配器将处于可用状态。
    unsafe fn init(&self, start: usize, end: usize) {
        self.0.lock().init(start, end);
    }
}

/// 实现 `GlobalAlloc` 接口以支持全局堆分配。
///
/// 本实现使 `KernelHeap` 可以作为 Rust 全局分配器使用，
/// 支持内核中 `Box`、`Vec` 等标准堆分配类型的底层内存管理。
///
/// `alloc` 和 `dealloc` 方法会加锁访问内部的 [`BuddySystem`] 分配器，
/// 从而保证在多核环境下的线程安全。
unsafe impl GlobalAlloc for KernelHeap {
    /// # 功能说明
    ///
    /// - `alloc`：根据指定的内存布局分配堆空间；
    /// 
    /// # 参数
    ///
    /// - `layout`：一个 [`Layout`] 对象，指定分配或释放的内存大小与对齐；
    /// # 返回值
    ///
    /// - `alloc` 返回一个满足给定 `layout` 的裸指针；若内存不足返回空指针；
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.lock().alloc(layout)
    }

    /// # 功能说明
    ///
    /// - `dealloc`：释放由 `alloc` 分配的堆空间，并尝试进行伙伴合并；
    /// # 参数
    ///
    /// - `layout`：一个 [`Layout`] 对象，指定分配或释放的内存大小与对齐；
    /// - `ptr`：待释放的内存指针，必须来自之前分配的有效地址；
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().dealloc(ptr, layout)
    }
}

/// 伙伴系统内存分配器的核心结构。
///
/// `BuddySystem` 是内核堆分配器的底层实现，采用经典的伙伴系统算法，
/// 将堆内存划分为以 2 的幂为大小的块，通过分裂和合并操作进行内存分配与回收。
///
/// 本结构记录了伙伴系统管理的内存范围、分配状态以及每个块大小等级的元信息，
/// 并在初始化完成后提供线程安全的内存操作接口（通常由 [`KernelHeap`] 封装）。
///
/// 初始化通过 [`BuddySystem::init`] 方法完成，
/// 分配与释放分别通过 `alloc()` 和 `dealloc()` 实现。
pub struct BuddySystem {
    /// 伙伴系统管理的起始物理地址（页对齐）。
    base: usize,

    /// 伙伴系统管理的实际结束地址（页对齐），不包括该地址本身。
    actual_end: usize,

    /// 支持的块大小等级数量，对应 log2(最大块数) + 1。
    ///
    /// 每个等级的块大小为 `2^k * LEAF_SIZE`。
    nsizes: usize,

    /// 标记该结构是否已完成初始化。
    ///
    /// 防止重复初始化，若已初始化再次调用 `init()` 将 panic。
    initialized: bool,

    /// 每个块大小等级对应的分配状态和空闲链表信息。
    ///
    /// 该字段为指向 `BuddyInfo` 切片的裸指针，需在初始化过程中手动构造并写入。
    /// 使用 `MaybeUninit` 包装，以避免未初始化内存的 UB。
    infos: MaybeUninit<*mut [BuddyInfo]>,
}


// since *mut [T] is not Send
unsafe impl Send for BuddySystem {}

impl BuddySystem {
    const fn uninit() -> Self {
        Self {
            base: 0,
            actual_end: 0,
            nsizes: 0,
            initialized: false, 
            infos: MaybeUninit::uninit(),
        }
    }

    /// 初始化伙伴系统内存分配器。
    ///
    /// 将 `[start, end)` 范围内的物理内存划入内核堆空间，
    /// 构造内部管理结构，包括空闲块链表、分配位图、分裂位图等，
    /// 并对所有内存页进行页对齐处理。完成初始化后，即可通过该结构执行分配与释放操作。
    /// 
    /// # 功能说明
    ///
    /// - 对传入的起始与结束地址进行页对齐，确定实际管理的堆内存区间；
    /// - 根据堆大小计算支持的块大小等级（`nsizes`），并为每一级分配对应的 [`BuddyInfo`]；
    /// - 为每一级块构造空闲链表（`free`）、分配状态位图（`alloc`）与分裂位图（`split`）；
    /// - 标记元数据与不可用内存块，避免误分配；
    /// - 初始化剩余内存为可分配区域，并检查内存总量一致性。
    /// 
    /// # 参数
    ///
    /// - `start`：堆管理区域的起始物理地址（不一定对齐）；
    /// - `end`：堆管理区域的结束物理地址（不一定对齐，排除该地址本身）；
    /// 
    /// # 返回值
    ///
    /// - 无返回值。成功执行后，`BuddySystem` 即处于可用状态。
    /// 
    /// # 可能的错误
    ///
    /// - 如果该函数被重复调用，`self.initialized` 为 `true`，将 panic：`"buddy system: init twice"`；
    /// - 若计算出的可用内存与期望值不一致，将 panic 并输出 meta/free/unavail 的差异；
    /// - 如果 `cur` 超出 `[start, end)` 范围，会导致非法内存访问或后续错误行为。
    /// 
    /// # 安全性
    ///
    /// - 函数为 `unsafe`，调用者必须确保 `start` 和 `end` 地址合法、可访问，且位于物理内存边界之内；
    /// - 本函数会修改大量裸内存并使用裸指针，必须保证在未使用该结构前完成一次性调用；
    /// - 初始化完成后，该结构进入不变式维护状态，不应再次调用该函数。
    unsafe fn init(&mut self, start: usize, end: usize) {
        if self.initialized {
            panic!("  buddy system: init twice");
        }

        // make sure start and end are both page aligned
        // and record the heap memory range: [self.base, self.end)
        let mut cur: usize = round_up(start, cmp::max(LEAF_SIZE, PGSIZE));
        self.base = cur;
        self.actual_end = round_down(end, cmp::max(LEAF_SIZE, PGSIZE));

        // compute the max pow of 2 smaller than size of [self.base, self.actual_end)
        self.nsizes = log2((self.actual_end-cur)/LEAF_SIZE) + 1;
        if self.actual_end - cur > blk_size(self.max_size()) {
            self.nsizes += 1;
        }

        println!("  buddy system: useful memory is {:#x} bytes", self.actual_end - self.base);
        println!("  buddy system: leaf size is {} bytes", LEAF_SIZE);
        println!("  buddy system: free lists have {} different sizes", self.nsizes);

        // alloc buddy infos
        // SAFETY: init all of the BuddyInfo
        let info_slice_ptr = init_slice_empty(&mut cur, self.nsizes);
        self.infos.as_mut_ptr().write(info_slice_ptr);


        // init free list and alloc space for alloc field
        for i in 0..self.nsizes {
            let nblk = self.n_blk(i);
            let info = self.get_info_mut(i);
            
            info.free.init();

            // SAFETY: init the alloc field of size i
            let alloc_size = round_up(nblk, 8)/8;
            let alloc_slice_ptr = init_slice_empty(&mut cur, alloc_size);
            info.alloc.as_mut_ptr().write(alloc_slice_ptr);
        }

        // alloc space for split field
        // blocks of size 0 no need to split
        for i in 1..self.nsizes {
            let nblk = self.n_blk(i);
            let info = self.get_info_mut(i);

            // SAFETY: init the split field of size i
            let split_size = round_up(nblk, 8)/8;
            let split_slice_ptr = init_slice_empty(&mut cur, split_size);
            info.split.as_mut_ptr().write(split_slice_ptr);
        }

        // cur address may not be aligned now
        cur = round_up(cur, LEAF_SIZE);

        // meta data lies between [base, cur)
        let meta = self.mark_meta(cur);

        // unavailable data lies between [self.actual_end, 2^(self.nsizes-1))
        // due to the memory size of buddy system is a power of 2
        let unavail = self.mark_unavail();
        
        // init free regions
        let free = self.init_free(cur);

        // check total memory
        if free != blk_size(self.max_size()) - meta - unavail {
            panic!("  buddy system: meta {}, free {}, unavail {}", meta, free, unavail);
        }

        self.initialized = true;
    }

    /// 根据给定的内存布局分配一个内存块。
    ///
    /// 使用伙伴系统算法，从空闲块链表中查找并分配一个满足 `layout` 要求的内存块，
    /// 如有必要会进行更大块的拆分操作以获得适配的最小可用块。
    /// 
    /// # 功能说明
    ///
    /// - 根据 `layout.size()` 和 `layout.align()`，计算所需的最小块等级；
    /// - 从空闲链表中查找第一个满足要求的块，如无可用块则返回空指针；
    /// - 若找到的块大于所需大小，则逐层拆分，释放多余的 buddy 到更小一级的空闲链表；
    /// - 最终返回一个满足大小和对齐要求的裸指针。
    /// 
    /// # 参数
    ///
    /// - `layout`: [`Layout`] 类型，指定所需内存块的大小与对齐要求。
    /// 
    /// # 返回值
    ///
    /// - 成功时返回一个指向所分配内存块的裸指针；
    /// - 如果内存不足或找不到满足要求的块，返回 `null_mut()`。
    /// 
    /// # 可能的错误
    ///
    /// - 若 `layout.align()` 大于页大小（`PGSIZE`），将触发 panic；
    /// - 若分配失败（例如所有块都已用尽），返回空指针；
    /// 
    /// # 安全性
    ///
    /// - 返回的指针未初始化，使用者需确保在使用前正确初始化内容；
    /// - 返回指针的生命周期由调用者负责，必须由对应的 `dealloc` 手动释放；
    /// - 分配器内部使用了裸指针与不安全内存操作，依赖正确初始化与不变式维护；
    fn alloc(&mut self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return ptr::null_mut()
        }

        // only guarantee the alignment not bigger than page size
        if layout.align() > PGSIZE {
            panic!("  buddy system: request layout alignment({}) bigger than PGSIZE({})",
                layout.align(), PGSIZE);
        }
        // note: the size of a value is always a multiple of its alignment
        // now we only have to consider the size

        // find the smallest block can contain the size
        let smalli = if layout.size() <= LEAF_SIZE {
            0 
        } else {
            (layout.size().next_power_of_two() / LEAF_SIZE).trailing_zeros() as usize
        };
        let mut sizei = smalli;
        while sizei < self.nsizes {
            let info = unsafe { self.get_info_mut(sizei) };
            if !info.free.is_empty() {
                break;
            }
            sizei += 1;
        }
        if sizei >= self.nsizes {
            // no free memory
            return ptr::null_mut()
        }

        // pop a block at self.infos[sizei]
        let info = unsafe { self.get_info_mut(sizei) };
        let raw_addr = unsafe { info.free.pop() };
        let bi = self.blk_index(sizei, raw_addr);
        unsafe { self.get_info_mut(sizei).alloc_set(bi, true); }

        // split the block until it reach smallest block size
        while sizei > smalli {            
            // split two buddies at sizei
            let bi = self.blk_index(sizei, raw_addr);
            let info = unsafe { self.get_info_mut(sizei) };
            info.split_set(bi, true);

            // alloc one buddy at sizei-1
            let bi1 = self.blk_index(sizei-1, raw_addr);
            let info1 = unsafe { self.get_info_mut(sizei-1) };
            info1.alloc_set(bi1, true);

            // free the other buddy at sizei-1
            let buddy_addr = raw_addr + blk_size(sizei-1);
            unsafe { info1.free.push(buddy_addr); }

            sizei -= 1;
        }

        raw_addr as *mut u8
    }

    /// 释放先前分配的内存块，并尝试进行伙伴合并。
    ///
    /// 根据给定的指针与内存布局信息，从伙伴系统中回收对应内存块，
    /// 若发现其伙伴块未被分配，则递归合并为更大一级的块，以减少碎片。
    /// 
    /// # 功能说明
    ///
    /// - 检查传入的 `ptr` 是否在管理范围内；
    /// - 通过 `split` 位图回推该内存块的分配等级；
    /// - 验证传入的布局是否匹配当前块大小；
    /// - 清除当前块的分配位，并与其伙伴尝试合并；
    /// 
    /// # 参数
    ///
    /// - `ptr`: 一个先前由 `alloc()` 返回的裸指针；
    /// - `layout`: 与原分配请求一致的 [`Layout`] 对象，指定大小和对齐；
    /// 
    /// # 返回值
    ///
    /// - 无返回值，函数执行后目标内存块被成功释放或合并回更大块；
    /// 
    /// # 可能的错误
    ///
    /// - 若 `ptr` 不在合法的堆地址范围内，则 panic：`"dealloc ptr out of range"`；
    /// - 若找不到该内存块对应的分裂标记，则 panic：`"dealloc cannot recycle ptr"`；
    /// - 若传入 `layout.size()` 大于当前块大小，则 panic，表示回收参数与分配不匹配；
    /// 
    /// # 安全性
    ///
    /// - 调用方必须保证传入的 `ptr` 是由当前分配器之前分配得到，
    ///   否则可能导致内存破坏；
    /// - `layout` 必须与原始分配请求完全一致；
    /// - 函数内部包含大量裸指针操作和不安全强制转换，依赖正确初始化和结构不变式；
    ///
    /// [`Layout`]: core::alloc::Layout
    fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
        // check ptr in range [self.base, self.actual_end)
        let mut raw_addr = ptr as usize;
        if raw_addr < self.base || raw_addr >= self.actual_end {
            panic!("  buddy system: dealloc ptr out of range");
        }

        // find the size of block pointed by ptr
        // and check with the layout
        let mut sizei = self.nsizes;
        for i in 0..self.max_size() {
            let bi = self.blk_index(i+1, raw_addr);
            let info = unsafe { self.get_info_mut(i+1) };
            if info.is_split_set(bi) {
                sizei = i;
                break;
            }
        }
        if sizei == self.nsizes {
            panic!("  buddy system: dealloc cannot recycle ptr");
        }

        // check layout
        if layout.size() > blk_size(sizei) {
            panic!("  buddy system: layout {:?} > blk size {}", layout, blk_size(sizei));
        }

        // free and coalesce
        while sizei < self.max_size() {
            let bi = self.blk_index(sizei, raw_addr);
            let buddyi = if bi % 2 == 0 { bi+1 } else { bi-1 };
            let info = unsafe { self.get_info_mut(sizei) };
            info.alloc_set(bi, false);
            
            // test if buddy is free
            if info.is_alloc_set(buddyi) {
                break;
            }
            let buddy_addr = self.blk_addr(sizei, buddyi);
            unsafe { (buddy_addr as *mut List).as_mut().unwrap().remove(); }
            if buddyi % 2 == 0 {
                raw_addr = buddy_addr;
            }

            // coalesce and continue
            sizei += 1;
            let spliti = self.blk_index(sizei, raw_addr);
            let info = unsafe { self.get_info_mut(sizei) };
            info.split_set(spliti, false);
        }

        let info = unsafe { self.get_info_mut(sizei) };
        unsafe { info.free.push(raw_addr); }
    }

    /// 标记伙伴系统用于元数据存储的内存区间为“已占用”状态。
    ///
    /// 本函数在初始化阶段调用，表示从堆起始地址 `base` 到当前指针 `cur` 之间的内存被用于
    /// 存储 allocator 的内部数据结构（如 `BuddyInfo`、位图、链表头等），
    /// 因此这些内存块不应被后续的分配器再利用。
    /// 
    /// # 功能说明
    ///
    /// - 计算元数据区域的大小，即 `[self.base, cur)` 区间；
    /// - 调用 [`mark`] 函数，将该内存区间在所有等级上标记为已分配；
    /// - 返回该区域占用的字节数，供后续一致性校验使用（如和可用块大小总和对比）；
    /// 
    /// # 参数
    ///
    /// - `cur`: 元数据区域的结束地址（不包含），应当在 `init()` 阶段动态计算得出；
    /// 
    /// # 返回值
    ///
    /// - `usize`：表示元数据区域的大小（以字节计），即 `cur - self.base`。
    fn mark_meta(&mut self, cur: usize) -> usize {
        let meta = cur - self.base;
        println!("  buddy system: alloc {:#x} bytes meta data", meta);
        self.mark(self.base, cur);
        meta
    }

    /// 标记由于对齐要求而不可用的内存区域为“已占用”状态。
    ///
    /// Buddy System 要求管理的总内存大小为 2 的幂，因此实际可用内存 `[base, actual_end)`
    /// 可能小于向上对齐后的总管理大小 `blk_size(max_size)`，
    /// 多出的这部分内存（即 `[actual_end, base + blk_size(max_size))`）
    /// 被视为不可分配区域，应当显式标记为“已占用”，以防被误用。
    /// 
    /// # 功能说明
    ///
    /// - 计算由于 2 的幂对齐造成的不可用内存大小；
    /// - 使用 [`mark`] 函数将该不可用区域标记为“已占用”状态；
    /// - 返回该区域的字节大小，用于后续校验（如总内存一致性检查）；
    /// 
    /// # 参数
    ///
    /// - 无参数。函数内部依赖于 `self.base`、`self.actual_end` 和 `self.max_size()` 的状态；
    /// 
    /// # 返回值
    ///
    /// - `usize`：被标记为不可用的内存大小（以字节计）；
    fn mark_unavail(&mut self) -> usize {
        let unavail = blk_size(self.max_size()) - (self.actual_end - self.base);
        println!("  buddy system: {:#x} bytes unavailable", unavail);
        self.mark(self.actual_end, self.actual_end + unavail);
        unavail
    }

    /// 将指定内存区间标记为“已占用”，用于元数据区域或不可用空间。
    ///
    /// 该函数在内存初始化阶段被调用，通常用于标记：
    /// - 元数据所占内存（如位图、链表结构等）
    /// - 由于对齐原因不能使用的尾部内存
    ///
    /// 它会遍历所有大小等级，并在每一级中将 `[left, right)` 区间覆盖的块标记为已分配，
    /// 并在大于 0 的等级中设置这些块的 `split` 位，防止后续错误合并。
    /// 
    /// # 功能说明
    ///
    /// - 遍历每个 sizei 等级（从小到大），计算该等级下 `[left, right)` 覆盖的块索引范围；
    /// - 对每个被覆盖的块：
    ///   - 设置其分配位（`alloc`）
    ///   - 若 sizei > 0，还设置其分裂位（`split`）
    /// - 这样这些块在分配或合并时将被跳过，不会误认为是空闲块。
    /// 
    /// # 参数
    ///
    /// - `left`: 需要标记为占用的起始地址，必须是 `LEAF_SIZE` 对齐；
    /// - `right`: 标记区间的结束地址（不包括该地址），也必须是 `LEAF_SIZE` 对齐；
    /// 
    /// # 返回值
    ///
    /// - 无返回值。执行后，`[left, right)` 区间所映射的所有块将在所有等级上被视为“已分配”。
    fn mark(&mut self, left: usize, right: usize) {
        assert_eq!(left % LEAF_SIZE, 0);
        assert_eq!(right % LEAF_SIZE, 0);

        for i in 0..self.nsizes {
            let mut bi = self.blk_index(i, left);
            let bj = self.blk_index_next(i, right);
            while bi < bj {
                let info = unsafe { self.get_info_mut(i) };

                // mark alloc
                info.alloc_set(bi, true);

                // mark split, skip size 0
                if i > 0 {
                    info.split_set(bi, true);
                }
                bi += 1;
            }
        }
    }

    /// 初始化 `[left, actual_end)` 区间内可分配的空闲块，并将其插入对应等级的 free list。
    ///
    /// 该函数在初始化阶段调用，前提是元数据区域与不可用区域已经通过 [`mark`] 标记为“已占用”，
    /// 本函数将其余未被占用的内存区间转换为合法的空闲块，并放入适当的 free list 中，
    /// 从而构建初始的空闲内存池。
    /// 
    /// # 功能说明
    ///
    /// - 遍历每个大小等级 `sizei`，尝试将 `[left, actual_end)` 范围内的空闲块加入 free list；
    /// - 对每个等级，调用 [`init_free_pair`] 尝试将未被占用、无法合并的 buddy 对作为独立块插入；
    /// - 返回总共插入的空闲字节数，用于与元数据与不可用内存对账；
    /// 
    /// # 参数
    ///
    /// - `left`: 可用区域的起始地址（必须已经跳过元数据与不可用区域）；
    /// 
    /// # 返回值
    ///
    /// - `usize`：成功插入到 free list 的空闲内存总字节数；
    fn init_free(&mut self, left: usize) -> usize {
        let right = self.actual_end;
        let mut free = 0;
        for i in 0..self.max_size() {
            let lbi = self.blk_index_next(i, left);
            let rbi = self.blk_index(i, right);
            free += self.init_free_pair(i, lbi);
            if left < right {
                free += self.init_free_pair(i, rbi);
            }
        }
        free
    }

    /// 初始化一对 buddy 块中的空闲块，并将其加入对应等级的 free list。
    ///
    /// 在初始化空闲内存时，遍历每一对 buddy（相邻的两个块），
    /// 若发现一块是空闲的而另一块已被标记为分配（如元数据或不可用区域），
    /// 则将空闲的那一块加入到对应等级的 free list 中，
    /// 从而避免错误合并并确保初始状态下的 free list 只包含真正可用的块。
    /// 
    /// # 功能说明
    ///
    /// - 计算当前块 `bi` 与其 buddy 的编号 `buddyi`；
    /// - 获取它们对应的物理地址，并检查它们的 `alloc` 位状态；
    /// - 如果这对 buddy 中只有一块是空闲的，则将该空闲块的地址加入 `free list[sizei]`；
    /// - 返回此次操作所插入的空闲块大小（单位：字节），否则返回 0 表示未插入；
    /// 
    /// # 参数
    ///
    /// - `sizei`: 当前块所属的大小等级，对应块大小为 `2^sizei * LEAF_SIZE`；
    /// - `bi`: 当前块在该等级中的块索引；
    /// 
    /// # 返回值
    ///
    /// - `usize`：此次插入的空闲块大小，若未插入任何块则返回 0；
    fn init_free_pair(&mut self, sizei: usize, bi: usize) -> usize {
        let buddyi = if bi % 2 == 0 { bi+1 } else { bi-1 };
        let blk_addr_bi = self.blk_addr(sizei, bi);
        let blk_addr_buddyi = self.blk_addr(sizei, buddyi);
        
        let info = unsafe { self.get_info_mut(sizei) };
        if info.is_alloc_set(bi) != info.is_alloc_set(buddyi) {
            // one buddy is free, the other is allocated
            unsafe {
                if info.is_alloc_set(bi) {
                    info.free.push(blk_addr_buddyi);
                } else {
                    info.free.push(blk_addr_bi);    
                }
            }
            blk_size(sizei)
        } else {
            0
        }
    }

    /// Get buddy info at certain index.
    ///
    /// SAFETY: must be called after the initialization of infos field.
    unsafe fn get_info_mut(&mut self, index: usize) -> &mut BuddyInfo {
        let info_slice_ptr = *self.infos.as_ptr();
        info_slice_ptr.get_unchecked_mut(index).as_mut().unwrap()
    }

    /// The largest block size.
    /// Also the last index into the buddy info array.
    #[inline]
    fn max_size(&self) -> usize {
        self.nsizes - 1
    }

    /// Number of block at size k, based on the total managed memory.
    #[inline]
    fn n_blk(&self, k: usize) -> usize {
        1 << (self.max_size() - k)
    }

    fn blk_index(&self, k: usize, addr: usize) -> usize {
        (addr - self.base) / blk_size(k)
    }

    fn blk_index_next(&self, k: usize, addr: usize) -> usize {
        let mut i = (addr - self.base) / blk_size(k);
        if (addr - self.base) % blk_size(k) > 0 {
            i += 1;
        }
        i
    }

    /// Receive size k and block index bi.
    /// Return the block's raw addr at this buddy system.
    fn blk_addr(&self, k: usize, bi: usize) -> usize {
        self.base + (bi * blk_size(k))
    }
}

/// Buddy info for block of a certain size k, k is a power of 2 
#[repr(C)]
struct BuddyInfo {
    free: List,                         // record blocks of a certain size
    alloc: MaybeUninit<*mut [u8]>,      // tell if a block is allocated
    split: MaybeUninit<*mut [u8]>,      // tell if a block is split into smaller size
}

impl BuddyInfo {
    /// SAFETY: must be called after the initialization of alloc field.
    unsafe fn get_alloc(&self, index: usize) -> &u8 {
        let alloc_slice_ptr = *self.alloc.as_ptr() as *const [u8];
        alloc_slice_ptr.get_unchecked(index).as_ref().unwrap()
    }

    /// SAFETY: must be called after the initialization of alloc field.
    unsafe fn get_alloc_mut(&mut self, index: usize) -> &mut u8 {
        let alloc_slice_ptr = *self.alloc.as_ptr();
        alloc_slice_ptr.get_unchecked_mut(index).as_mut().unwrap()
    }

    /// SAFETY: must be called after the initialization of split field.
    unsafe fn get_split(&self, index: usize) -> &u8 {
        let split_slice_ptr = *self.split.as_ptr() as *const [u8];
        split_slice_ptr.get_unchecked(index).as_ref().unwrap()
    }

    /// SAFETY: must be called after the initialization of split field.
    unsafe fn get_split_mut(&mut self, index: usize) -> &mut u8 {
        let split_slice_ptr = *self.split.as_ptr();
        split_slice_ptr.get_unchecked_mut(index).as_mut().unwrap()
    }

    fn alloc_set(&mut self, index: usize, set_or_clear: bool) {
        let i1 = index / 8;
        let i2 = index % 8;
        unsafe { self.get_alloc_mut(i1).set_bit(i2, set_or_clear); }
    }

    fn split_set(&mut self, index: usize, set_or_clear: bool) {
        let i1 = index / 8;
        let i2 = index % 8;
        unsafe { self.get_split_mut(i1).set_bit(i2, set_or_clear); }
    }

    fn is_alloc_set(&self, index: usize) -> bool {
        let i1 = index / 8;
        let i2 = index % 8;
        unsafe { self.get_alloc(i1).get_bit(i2) }
    }

    fn is_split_set(&self, index: usize) -> bool {
        let i1 = index / 8;
        let i2 = index % 8;
        unsafe { self.get_split(i1).get_bit(i2) }
    }
}

/// Init the uninit raw slice wrapped in MaybeUninit with empty data, typically 0.
/// The passed-in T should have repr(C).
/// Return an initialized raw slice ptr.
unsafe fn init_slice_empty<T>(cur: &mut usize, len: usize) -> *mut [T] {
    let raw_ptr = *cur as *mut T;
    *cur += size_of::<T>() * len;
    ptr::write_bytes(raw_ptr, 0, len);
    ptr::slice_from_raw_parts_mut(raw_ptr, len)
}

#[inline]
fn round_up(n: usize, size: usize) -> usize {
    (((n-1)/size)+1)*size
}

#[inline]
fn round_down(n: usize, size: usize) -> usize {
    (n/size)*size
}

fn log2(mut n: usize) -> usize {
    let mut k = 0;
    while n > 1 {
        k += 1;
        n >>= 1;
    }
    k
}

#[inline]
fn blk_size(k: usize) -> usize {
    (1 << k) * LEAF_SIZE
}


#[cfg(feature = "unit_test")]
pub mod tests {
    use super::*;
    use crate::consts;
    use crate::proc::cpu_id;
    use crate::mm::pagetable::PageTable;
    use core::sync::atomic::{AtomicU8, Ordering};

    pub fn alloc_simo() {
        // use NSMP to synchronize testing pr's spinlock
        static NSMP: AtomicU8 = AtomicU8::new(0);
        NSMP.fetch_add(1, Ordering::Relaxed);
        while NSMP.load(Ordering::Relaxed) != NSMP as u8 {}

        let id = unsafe { cpu_id() };

        for _ in 0..10 {
            let page_table = PageTable::new();
            println!("hart {} alloc page table at {:#x}", id, page_table.addr());
        }

        NSMP.fetch_sub(1, Ordering::Relaxed);
        while NSMP.load(Ordering::Relaxed) != 0 {}
    }
}
