use core::arch::asm;
use core::convert::{TryFrom, Into};
use core::mem;

use crate::consts::{
    CLINT, CLINT_MAP_SIZE, KERNBASE, PHYSTOP, PLIC, PLIC_MAP_SIZE, UART0, UART0_MAP_SIZE, VIRTIO0,
    VIRTIO0_MAP_SIZE, TRAMPOLINE, PGSIZE
};
use crate::register::satp;
use super::{Addr, PageTable, PhysAddr, PteFlag, VirtAddr, RawSinglePage, RawDoublePage, RawQuadPage};

/// 内核页表（Kernel Page Table）
/// 
/// 这是内核使用的全局页表根，负责管理整个内核虚拟地址空间的页表映射。
/// 在xv6教学操作系统中，此数据结构用于维护内核代码段、数据段、设备内存映射等
/// 的虚拟地址到物理地址的映射关系。
/// 
/// 由于页表需要在内核初始化期间动态修改，因此采用 `static mut` 定义为可变静态变量。
/// 
/// # 用途
/// - 作为内核页表根，供 `satp` 寄存器加载，完成地址转换功能。
/// - 通过该页表，内核能够访问物理内存中的设备寄存器、内核自身代码和数据。
/// - 支持后续对页表的动态映射和修改操作，如添加新映射。
/// 
static mut KERNEL_PAGE_TABLE: PageTable = PageTable::empty();

/// 初始化当前处理器核心的内核虚拟内存页表。  
/// 该函数将内核页表的物理页号写入 `satp` 寄存器，启用分页机制，  
/// 并执行 `sfence.vma zero, zero` 指令刷新地址转换缓存（TLB），  
/// 保证页表修改立即生效。
pub unsafe fn kvm_init_hart() {
    satp::write(KERNEL_PAGE_TABLE.as_satp());
    asm!("sfence.vma zero, zero");
}

/// # 功能说明
/// 初始化内核虚拟内存页表的映射，建立内核空间的虚拟地址到物理地址的映射关系。  
/// 包括对设备寄存器（UART0、VIRTIO0、CLINT、PLIC）、内核代码段、内核数据段、以及陷阱跳板（trampoline）  
/// 等关键内存区域的映射，并设置对应的访问权限（只读、可写、可执行）。  
/// 还通过断言验证了原始页结构（RawSinglePage、RawDoublePage、RawQuadPage）与页表结构的内存布局一致性。
///
/// # 参数
/// 无参数。
///
/// # 返回值
/// 无返回值。
///
/// # 可能的错误
/// - 若外部符号 `etext` 或 `trampoline` 地址不正确，可能导致映射异常。  
/// - `kvm_map` 函数调用可能因重复映射、地址越界等原因 panic。  
/// - `VirtAddr::try_from` 和 `PhysAddr::try_from` 转换失败时会 panic（调用 unwrap）。
///
/// # 安全性
/// - 此函数标记为 `unsafe`，调用者需保证内存映射区域的正确性和唯一性，避免地址冲突。  
/// - 该函数操作全局静态可变变量 `KERNEL_PAGE_TABLE`，必须在单线程或适当同步环境下调用。  
/// - 运行时调用依赖外部符号，必须确保链接器脚本和相关代码匹配。  
/// - 适用于内核启动初始化阶段，且不应在多核并发环境下随意调用。
pub unsafe fn kvm_init() {
    // check if RawPages and PageTable have the same mem layout
    debug_assert_eq!(mem::size_of::<RawSinglePage>(), PGSIZE);
    debug_assert_eq!(mem::align_of::<RawSinglePage>(), PGSIZE);
    debug_assert_eq!(mem::size_of::<RawSinglePage>(), mem::size_of::<PageTable>());
    debug_assert_eq!(mem::align_of::<RawSinglePage>(), mem::align_of::<PageTable>());
    debug_assert_eq!(mem::size_of::<RawDoublePage>(), PGSIZE*2);
    debug_assert_eq!(mem::align_of::<RawDoublePage>(), PGSIZE);
    debug_assert_eq!(mem::size_of::<RawQuadPage>(), PGSIZE*4);
    debug_assert_eq!(mem::align_of::<RawQuadPage>(), PGSIZE);

    // uart registers
    kvm_map(
        VirtAddr::from(UART0),
        PhysAddr::from(UART0),
        UART0_MAP_SIZE,
        PteFlag::R | PteFlag::W,
    );

    // virtio mmio disk interface
    kvm_map(
        VirtAddr::from(VIRTIO0),
        PhysAddr::from(VIRTIO0),
        VIRTIO0_MAP_SIZE,
        PteFlag::R | PteFlag::W,
    );

    // CLINT
    kvm_map(
        VirtAddr::from(CLINT),
        PhysAddr::from(CLINT),
        CLINT_MAP_SIZE,
        PteFlag::R | PteFlag::W,
    );

    // PLIC
    kvm_map(
        VirtAddr::from(PLIC),
        PhysAddr::from(PLIC),
        PLIC_MAP_SIZE,
        PteFlag::R | PteFlag::W,
    );

    // etext exported out of kernel.ld
    // supposed to be page(0x1000) aligned
    extern "C" {
        fn etext();
    }
    let etext = etext as usize;

    // map kernel text executable and read-only.
    kvm_map(
        VirtAddr::from(KERNBASE),
        PhysAddr::from(KERNBASE),
        etext - Into::<usize>::into(KERNBASE),
        PteFlag::R | PteFlag::X,
    );

    // map kernel data and the physical RAM we'll make use of.
    kvm_map(
        VirtAddr::try_from(etext).unwrap(),
        PhysAddr::try_from(etext).unwrap(),
        usize::from(PHYSTOP) - etext,
        PteFlag::R | PteFlag::W,
    );

    // map the trampoline for trap entry/exit to
    // the highest virtual address in the kernel.
    extern "C" {
        fn trampoline();
    }
    kvm_map(
        VirtAddr::from(TRAMPOLINE),
        PhysAddr::try_from(trampoline as usize).unwrap(),
        PGSIZE,
        PteFlag::R | PteFlag::X
    );
}

/// 在内核全局页表 `KERNEL_PAGE_TABLE` 上建立虚拟地址到物理地址的映射。  
/// 映射从虚拟地址 `va` 开始，长度为 `size` 字节，权限由 `perm` 指定。  
/// 该函数负责调用底层页表映射方法，添加连续页的映射关系。
pub unsafe fn kvm_map(va: VirtAddr, pa: PhysAddr, size: usize, perm: PteFlag) {
    #[cfg(feature = "verbose_init_info")]
    println!(
        "kvm_map: va={:#x}, pa={:#x}, size={:#x}",
        va.as_usize(),
        pa.as_usize(),
        size
    );

    if let Err(err) = KERNEL_PAGE_TABLE.map_pages(va, size, pa, perm) {
        panic!("kvm_map: {}", err);
    }
}

/// # 功能说明
/// 将内核虚拟地址 `va` 转换为对应的物理地址。  
/// 该函数通过页表查找 `va` 对应的页表项，验证其有效性，  
/// 并返回物理页基址加上页内偏移，完成虚拟地址到物理地址的映射。
///
/// # 参数
/// - `va`: 需要转换的内核虚拟地址，地址不必页对齐。
///
/// # 返回值
/// 返回对应的物理地址（`u64` 类型）。
///
/// # 可能的错误
/// - 如果 `va` 未映射（页表项不存在），函数将 panic。  
/// - 如果页表项无效（即 `pte.is_valid()` 返回 false），函数将 panic。
///
/// # 安全性
/// - 标记为 `unsafe`，调用者需确保传入的虚拟地址有效且已正确映射。  
/// - 直接访问全局可变页表，可能导致数据竞争或非法访问，需在合适的环境下调用。  
/// - panic 会导致内核异常中断，应在调用前确保虚拟地址安全。
pub unsafe fn kvm_pa(va: VirtAddr) -> u64 {
    let off: u64 = (va.as_usize() % PGSIZE) as u64;
    match KERNEL_PAGE_TABLE.walk(va) {
        Some(pte) => {
            if !pte.is_valid() {
                panic!("kvm_pa: va={:?} mapped pa not valid", va);
            }
            pte.as_phys_addr().as_usize() as u64 + off
        }
        None => {
            panic!("kvm_pa: va={:?} no mapped pa", va);
        }
    }
}
