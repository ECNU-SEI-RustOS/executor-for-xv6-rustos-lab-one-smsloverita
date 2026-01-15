use core::sync::atomic::{AtomicBool, Ordering};

use crate::driver::{virtio_disk::DISK, console};
use crate::register::tp;
use crate::fs::BCACHE;
use crate::mm::kalloc::KERNEL_HEAP;
use crate::mm::{kvm_init, kvm_init_hart};
use crate::plic;
use crate::process::{PROC_MANAGER, CPU_MANAGER};
use crate::trap::trap_init_hart;

/// 用于多核启动同步的全局原子布尔变量。
///
/// `STARTED` 表示主核（cpuid == 0）是否完成了内核的全局初始化。
/// 所有从核（cpuid != 0）在启动时会自旋等待该变量变为 `true`，以确保主核先完成必要的系统初始化，
/// 如堆空间、页表、设备中断控制器（PLIC）、块缓存等资源的设置。
static STARTED: AtomicBool = AtomicBool::new(false);

/// 内核主入口函数，完成多核系统中各 hart（硬件线程）的初始化流程。
///
/// 此函数由启动汇编代码在每个 hart 上调用，负责根据 CPU ID 判断并执行主核或从核的初始化逻辑。
/// - 主核（cpuid == 0）将进行全局资源的初始化，如内核堆、页表、设备中断、磁盘驱动、进程管理等，
///   并创建第一个用户进程。
/// - 从核则等待主核初始化完成后，初始化各自的页表、陷入向量和中断控制器。
///
/// 该函数在初始化完成后，所有 hart 会进入调度器，开始调度运行用户/内核进程。
///
/// # 参数
/// 无参数。
///
/// # 返回值
/// 该函数永不返回（返回类型为 `!`），调用后将转入调度器无限循环运行。
///
/// # 可能的错误
/// 此函数本身不会返回错误，但由于涉及大量系统初始化操作，
/// 如果某些底层组件（如分页系统、PLIC、磁盘控制器）未正确实现，
/// 则可能导致内核 panic 或硬件异常。
///
/// # 安全性
/// 此函数为 `unsafe`，因为：
/// - 它在未建立 Rust 安全抽象的早期阶段直接操作硬件资源；
/// - 多数全局资源尚未初始化，使用不当可能造成数据竞争或未定义行为；
/// - 它会调用多个底层初始化函数，这些函数可能执行裸指针操作或依赖外部状态（如硬件寄存器）；
/// - 要求调用者确保在唯一 hart 上执行早期初始化逻辑，避免多核同时初始化同一全局资源。
pub unsafe fn rust_main() -> ! {
    // explicitly use tp::read here
    let cpuid = tp::read();
    
    if cpuid == 0 {
        console::init();
        println!();
        println!("xv6-rust is booting");
        println!();
        KERNEL_HEAP.kinit();
        kvm_init(); // init kernel page table
        PROC_MANAGER.proc_init(); // process table
        kvm_init_hart(); // trun on paging
        trap_init_hart(); // install kernel trap vector
        plic::init();
        plic::init_hart(cpuid);
        BCACHE.binit();             // buffer cache
        DISK.lock().init();         // emulated hard disk
        PROC_MANAGER.user_init();   // first user process

        STARTED.store(true, Ordering::SeqCst);
    } else {
        while !STARTED.load(Ordering::SeqCst) {}

        println!("hart {} starting", cpuid);
        kvm_init_hart(); // turn on paging
        trap_init_hart(); // install kernel trap vector
        plic::init_hart(cpuid); // ask PLIC for device interrupts
    }

    #[cfg(feature = "unit_test")]
    super::test_main_entry();

    CPU_MANAGER.scheduler();
}
