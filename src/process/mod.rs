use array_macro::array;

use core::convert::TryFrom;
use core::ptr;
use core::mem;
use core::sync::atomic::Ordering;

use crate::consts::{NPROC, PGSIZE, TRAMPOLINE, fs::ROOTDEV};
use crate::mm::{kvm_map, PhysAddr, PteFlag, VirtAddr, RawPage, RawSinglePage, PageTable, RawQuadPage};
use crate::spinlock::SpinLock;
use crate::trap::user_trap_ret;
use crate::fs;

pub use cpu::{CPU_MANAGER, CpuManager};
pub use cpu::{push_off, pop_off};
pub use proc::Proc;

mod context;
mod proc;
mod cpu;
mod trapframe;

use context::Context;
use proc::ProcState;
use trapframe::TrapFrame;

/// 全局进程管理器（Process Manager）
/// 
/// 这是一个模仿 xv6 操作系统的教学内核中的核心进程管理结构体的唯一实例，
/// 用于维护和管理系统中所有进程的生命周期、状态和调度相关数据。
/// 
/// # 用途
/// - 持有固定大小的进程表（`table`），包含所有进程的状态和资源信息。
/// - 分配新的进程标识符（PID）。
/// - 负责进程的创建、初始化、唤醒、阻塞、退出和等待等管理操作。
/// - 管理进程间的父子关系。
/// - 提供进程调度相关的接口，如分配可运行进程等。
/// 
/// # 并发安全性
/// - 该静态变量为可变全局，访问时需要使用 `unsafe`，
///   代码中部分操作通过自旋锁保护特定成员，但整体访问仍不完全安全。
/// - 设计上假定访问该变量的代码必须自行保证同步和互斥。
/// 
/// # 使用限制
/// - 仅初始化一次，由第一个 CPU 核心调用 `proc_init` 和 `user_init` 进行初始化。
/// - 后续所有对进程管理的操作都通过此结构体进行。
pub static mut PROC_MANAGER: ProcManager = ProcManager::new();


/// 进程管理器（Process Manager）
///
/// 这是一个模仿 xv6 的教学操作系统内核中用于管理所有进程的核心结构体，
/// 负责维护系统中所有进程的状态、父子关系、PID 分配以及调度相关操作。
/// 
/// 主要功能包括：
/// - 存储固定数量的进程表，每个元素代表一个进程。
/// - 管理进程的父子关系映射。
/// - 维护初始进程索引（通常为第一个进程）。
/// - 分配并维护全局唯一的进程标识符（PID）。
/// 
/// 并发控制方面，通过自旋锁保护父进程关系和 PID 计数器，
/// 但访问整个进程表本身未加锁，使用时需注意并发安全。
pub struct ProcManager {
    /// 进程表，存放系统中所有的进程结构体，数量固定为 `NPROC`。
    table: [Proc; NPROC],

    /// 进程父子关系映射表，索引为子进程，值为对应父进程的索引。
    /// 受自旋锁保护以保证多线程环境下的安全访问。
    parents: SpinLock<[Option<usize>; NPROC]>,

    /// 初始进程在进程表中的索引，通常为 0，代表系统启动后的第一个进程。
    init_proc: usize,

    /// 全局进程 ID 分配器，负责分配唯一的 PID，受自旋锁保护以保证并发安全。
    pid: SpinLock<usize>,
}

impl ProcManager {
    const fn new() -> Self {
        Self {
            table: array![i => Proc::new(i); NPROC],
            parents: SpinLock::new(array![_ => None; NPROC], "proc parents"),
            init_proc: 0,
            pid: SpinLock::new(0, "pid"),
        }
    }

    /// # 功能说明
    /// 
    /// 初始化进程管理器中所有进程的内核栈空间。
    /// 具体操作包括为每个进程分配一段连续的物理页（4 页大小），
    /// 并在内核虚拟地址空间中映射这段内存作为内核栈，
    /// 同时在其上方设置一个保护页（无效页）作为栈溢出的保护。
    /// 
    /// 该函数通常由系统启动时第一个 CPU 核心调用一次，完成内核栈的初始化。
    /// 
    /// # 参数
    /// 
    /// - `&mut self`：进程管理器的可变引用，允许修改进程表中进程的内核栈地址。
    /// 
    /// # 返回值
    /// 
    /// - 无返回值。
    /// 
    /// # 可能的错误
    /// 
    /// - 该函数未显式处理分配失败或映射失败的情况，
    ///   假定物理页分配和映射均成功。
    /// - 如果内存分配或映射异常，可能导致未定义行为。
    /// 
    /// # 安全性
    /// 
    /// - 本函数使用了 `unsafe`，调用者必须确保仅由初始硬件线程调用，
    ///   并且在调用时没有并发访问 `ProcManager`，避免数据竞争。
    /// - 内存映射操作涉及底层指针转换和物理地址操作，
    ///   需要保证地址转换正确且符合内存管理单元的规范。
    /// - 此函数假设 `kvm_map` 成功完成映射，未做错误检查。
    pub unsafe fn proc_init(&mut self) {
        for (pos, p) in self.table.iter_mut().enumerate() {
            // Allocate a page for the process's kernel stack.
            // Map it high in memory, followed by an invalid
            // guard page.
            let pa = RawQuadPage::new_zeroed() as usize;
            let va = kstack(pos);
            kvm_map(
                VirtAddr::try_from(va).unwrap(),
                PhysAddr::try_from(pa).unwrap(),
                PGSIZE*4,
                PteFlag::R | PteFlag::W,
            );
            p.data.get_mut().set_kstack(va);
        }
    }

    /// # 功能说明
    /// 
    /// 分配一个唯一的进程标识符（PID）。
    /// 该函数通过自旋锁保护，支持多线程并发调用，
    /// 确保每次调用返回的 PID 都是唯一且递增的。
    /// 
    /// # 参数
    /// 
    /// - `&self`：对进程管理器的不可变引用，
    ///   内部通过自旋锁保证对 PID 计数器的互斥访问。
    /// 
    /// # 返回值
    /// 
    /// - 返回分配的唯一 PID，类型为 `usize`。
    /// 
    /// # 可能的错误
    /// 
    /// - 本函数未检测 PID 溢出或重复的异常情况，
    ///   在极端情况下（PID 达到最大值）可能产生错误。
    /// 
    /// # 安全性
    /// 
    /// - 函数内部使用自旋锁保护 PID 计数器，
    ///   保证多线程环境下的安全访问。
    /// - 调用此函数本身是安全的，无需额外 `unsafe` 块。
    fn alloc_pid(&self) -> usize {
        let ret_pid: usize;
        let mut pid = self.pid.lock();
        ret_pid = *pid;
        *pid += 1;
        drop(pid);
        ret_pid
    }

    /// # 功能说明
    /// 
    /// 在进程表中查找一个状态为 `UNUSED` 的空闲进程条目，
    /// 如果找到则为该进程分配新的 PID，初始化运行内核所需的状态，
    /// 包括分配陷阱帧（trapframe）和页表，
    /// 并将进程状态设置为 `ALLOCATED`。
    /// 返回该已分配但尚未运行的进程的可变引用。
    /// 
    /// # 参数
    /// 
    /// - `&mut self`：对进程管理器的可变引用，允许修改进程表。
    /// 
    /// # 返回值
    /// 
    /// - 返回 `Some(&mut Proc)`，表示成功分配并初始化了一个进程。
    /// - 返回 `None`，表示没有找到可用的空闲进程，或资源分配失败（如内存不足）。
    /// 
    /// # 可能的错误
    /// 
    /// - 分配陷阱帧或页表失败时，会返回 `None`，
    ///   表示无法完成新进程的分配。
    /// - 该函数当前未实现OOM（内存不足）恢复机制，
    ///   资源分配失败直接放弃。
    /// 
    /// # 安全性
    /// 
    /// - 分配陷阱帧时使用了 `unsafe`，调用 `RawSinglePage::try_new_zeroed()`，
    ///   需要保证底层内存分配正确且有效。
    fn alloc_proc(&mut self) ->
        Option<&mut Proc>
    {
        let new_pid = self.alloc_pid();

        for p in self.table.iter_mut() {
            let mut guard = p.excl.lock();
            match guard.state {
                ProcState::UNUSED => {
                    // holding the process's excl lock,
                    // so manager can modify its private data
                    let pd = p.data.get_mut();

                    // alloc trapframe
                    pd.tf = unsafe { RawSinglePage::try_new_zeroed().ok()? as *mut TrapFrame };

                    debug_assert!(pd.pagetable.is_none());
                    match PageTable::alloc_proc_pagetable(pd.tf as usize) {
                        Some(pgt) => pd.pagetable = Some(pgt),
                        None => {
                            unsafe { RawSinglePage::from_raw_and_drop(pd.tf as *mut u8); }
                            return None
                        },
                    }
                    pd.init_context();
                    guard.pid = new_pid;
                    guard.state = ProcState::ALLOCATED;

                    drop(guard);
                    return Some(p)
                },
                _ => drop(guard),
            }
        }

        None
    }

    /// # 功能说明
    ///
    /// 在进程表中查找第一个状态为 `RUNNABLE` 的进程，
    /// 将其状态修改为 `ALLOCATED`，
    /// 并返回该进程的可变引用，
    /// 返回时不持有该进程的锁，
    /// 该函数通常由各 CPU 的调度器调用以选取下一个运行的进程。
    ///
    /// # 参数
    ///
    /// - `&mut self`：进程管理器的可变引用，允许修改进程状态。
    ///
    /// # 返回值
    ///
    /// - 返回 `Some(&mut Proc)` 表示找到一个可运行的进程并分配成功。
    /// - 返回 `None` 表示当前没有可运行的进程。
    ///
    /// # 可能的错误
    ///
    /// - 无明显错误返回，但若存在并发访问冲突，可能导致调度延迟或饥饿。
    ///
    /// # 安全性
    ///
    /// - 通过持有进程的 `excl` 自旋锁保证状态修改的原子性，避免竞态条件。
    /// - 返回时释放了锁，调用者需确保使用该进程指针时的并发安全。
    fn alloc_runnable(&mut self) ->
        Option<&mut Proc>
    {
        for p in self.table.iter_mut() {
            let mut guard = p.excl.lock();
            match guard.state {
                ProcState::RUNNABLE => {
                    guard.state = ProcState::ALLOCATED;
                    drop(guard);
                    return Some(p)
                },
                _ => {
                    drop(guard);
                },
            }
        }

        None
    }

    /// # 功能说明
    ///
    /// 初始化系统的第一个用户进程。
    /// 该函数调用 `alloc_proc` 分配一个新的进程结构，
    /// 执行该进程的用户态初始化逻辑，
    /// 并将其状态设置为 `RUNNABLE`，
    /// 准备被调度执行。
    ///
    /// # 参数
    ///
    /// - `&mut self`：进程管理器的可变引用，允许修改进程表。
    ///
    /// # 返回值
    ///
    /// - 无返回值。
    ///
    /// # 可能的错误
    ///
    /// - 如果所有进程均非 UNUSED 状态，`alloc_proc` 返回 `None`，
    ///   此时函数会因 `expect` 调用而导致 panic。
    ///
    /// # 安全性
    ///
    /// - 函数标记为 `unsafe`，调用者必须确保：
    ///   - 仅由系统启动时的初始硬件线程（hart）调用一次。
    ///   - 初始进程在进程表中的索引为 0，
    ///     并且该索引对应的进程尚未被占用。
    /// - 在调用期间不允许并发访问 `ProcManager`，避免数据竞争。
    pub unsafe fn user_init(&mut self) {
        let p = self.alloc_proc()
            .expect("all process should be unused");
        p.user_init();
        let mut guard = p.excl.lock();
        guard.state = ProcState::RUNNABLE;
    }

    /// 检查给定的进程是否是init
    fn is_init_proc(&self, p: &Proc) -> bool {
        ptr::eq(&self.table[0], p)
    }

    /// # 功能说明
    ///
    /// 唤醒所有阻塞在指定通道 `channel` 上的进程。
    /// 遍历进程表，查找处于 `SLEEPING` 状态且等待通道为 `channel` 的进程，
    /// 将它们的状态修改为 `RUNNABLE`，
    /// 使这些进程能够被调度器选中运行。
    ///
    /// 注意：调用此函数时，不能持有任何进程的锁，以避免死锁。
    ///
    /// # 参数
    ///
    /// - `&self`：对进程管理器的不可变引用，用于访问进程表。
    /// - `channel: usize`：等待通道标识，唤醒所有阻塞在此通道的进程。
    ///
    /// # 返回值
    ///
    /// - 无返回值。
    ///
    /// # 可能的错误
    ///
    /// - 如果在调用此函数时持有了任一进程的锁，可能导致死锁。
    /// - 并发情况下，若其他线程同时修改进程状态，可能存在竞态风险。
    ///
    /// # 安全性
    ///
    /// - 函数内部对每个进程状态修改通过持有进程的自旋锁 `excl` 保护，
    ///   保证了修改操作的线程安全。
    /// - 调用者必须保证调用时未持有任何进程锁，避免潜在死锁。
    pub fn wakeup(&self, channel: usize) {
        for p in self.table.iter() {
            let mut guard = p.excl.lock();
            if guard.state == ProcState::SLEEPING && guard.channel == channel {
                guard.state = ProcState::RUNNABLE;
            }
            drop(guard);
        }
    }

    /// # 功能说明
    ///
    /// 设置指定子进程的父进程索引。
    /// 将 `child_i` 索引的子进程的父进程设置为 `parent_i`，
    /// 更新父子关系映射表。
    ///
    /// # 参数
    ///
    /// - `&self`：进程管理器的不可变引用，用于访问和修改父子关系映射。
    /// - `child_i: usize`：子进程在进程表中的索引。
    /// - `parent_i: usize`：父进程在进程表中的索引。
    ///
    /// # 返回值
    ///
    /// - 无返回值。
    ///
    /// # 可能的错误
    ///
    /// - 调用时如果 `child_i` 超出范围，会导致索引越界（panic）。
    /// - 调用前若该子进程已经有父进程，则会触发调试断言失败。
    ///
    /// # 安全性
    ///
    /// - 通过 `parents` 自旋锁保证对父子关系映射的安全访问和修改。
    /// - 调用者需保证索引合法且调用时环境符合并发访问规则，避免数据竞争。
    fn set_parent(&self, child_i: usize, parent_i: usize) {
        let mut guard = self.parents.lock();
        let ret = guard[child_i].replace(parent_i);
        debug_assert!(ret.is_none());
        drop(guard);
    }

    /// # 功能说明
    ///
    /// 使指定进程进入退出状态，执行退出清理流程。
    /// 具体包括关闭进程打开的文件，
    /// 将其子进程的父进程重新指向初始进程，
    /// 唤醒相关父进程，
    /// 设置退出状态并将进程状态改为 `ZOMBIE`，
    /// 最后调用调度器切换进程上下文，不返回。
    ///
    /// # 参数
    ///
    /// - `&self`：进程管理器的不可变引用，允许访问和修改进程相关数据。
    /// - `exit_pi: usize`：要退出的进程在进程表中的索引。
    /// - `exit_status: i32`：进程退出状态码，用于父进程查询。
    ///
    /// # 返回值
    ///
    /// - 无返回值。函数内部调用调度器后不会返回，
    ///   最后通过 `unreachable!` 宏标明该代码路径不应继续执行。
    ///
    /// # 可能的错误
    ///
    /// - 如果试图退出的是初始进程（`init_proc`），会触发 panic，
    ///   因为初始进程不允许退出。
    /// - 代码中假设进程索引和父子关系合法，
    ///   若数据结构异常可能导致未定义行为。
    ///
    /// # 安全性
    ///
    /// - 调用过程中涉及多处 `unsafe`，
    ///   包括对进程数据的裸指针操作和上下文获取，
    ///   需保证对应进程数据有效且未被其他线程破坏。
    /// - 持有和释放自旋锁时保证并发安全，
    ///   通过锁保护防止数据竞态。
    /// - 调用调度器切换上下文时，
    ///   确保当前 CPU 和进程状态正确，避免死锁或调度异常。
    fn exiting(&self, exit_pi: usize, exit_status: i32) {
        if exit_pi == self.init_proc {
            panic!("init process exiting");
        }

        unsafe { self.table[exit_pi].data.get().as_mut().unwrap().close_files(); }

        let mut parent_map = self.parents.lock();

        // Set the children's parent to init process.
        let mut have_child = false;
        for child in parent_map.iter_mut() {
            match child {
                Some(parent) if *parent == exit_pi => {
                    *parent = self.init_proc;
                    have_child = true;
                },
                _ => {},
            }
        }
        if have_child {
            self.wakeup(&self.table[self.init_proc] as *const Proc as usize);
        }
        let exit_parenti = *parent_map[exit_pi].as_ref().unwrap();
        self.wakeup(&self.table[exit_parenti] as *const Proc as usize);

        let mut exit_pexcl = self.table[exit_pi].excl.lock();
        exit_pexcl.exit_status = exit_status;
        exit_pexcl.state = ProcState::ZOMBIE;
        drop(parent_map);
        unsafe {
            let exit_ctx = self.table[exit_pi].data.get().as_mut().unwrap().get_context();
            CPU_MANAGER.my_cpu_mut().sched(exit_pexcl, exit_ctx);
        }

        unreachable!("exiting {}", exit_pi);
    }

    /// # 功能说明
    ///
    /// 父进程等待其任一子进程退出（进入 ZOMBIE 状态）。
    /// 如果找到已退出的子进程，将子进程的退出状态复制到用户空间，
    /// 清理子进程资源，解除父子关系映射，
    /// 并返回该子进程的 PID。
    /// 如果没有子进程或调用进程被杀死，则返回错误。
    /// 若存在子进程但均未退出，调用进程将进入睡眠状态，
    /// 直到被唤醒重新检测。
    ///
    /// # 参数
    ///
    /// - `&self`：进程管理器的不可变引用，用于访问进程表和父子关系。
    /// - `pi: usize`：调用该函数的父进程在进程表中的索引。
    /// - `addr: usize`：用户空间地址，
    ///   若非零，退出状态将复制到该地址。
    ///
    /// # 返回值
    ///
    /// - `Ok(usize)`：返回已退出子进程的 PID。
    /// - `Err(())`：表示没有子进程可等待，或者调用进程被杀死。
    ///
    /// # 可能的错误
    ///
    /// - 如果用户空间地址无效或拷贝失败，返回错误。
    /// - 如果无子进程或调用进程已被杀，返回错误。
    ///
    /// # 安全性
    ///
    /// - 使用了多处 `unsafe`，访问裸指针和非线程安全的结构，
    ///   需保证对应内存有效且数据未被并发破坏。
    /// - 通过持有自旋锁保护父子映射表的访问，防止竞态。
    /// - 调用 `sleep` 使调用进程阻塞，等待唤醒重新检测，
    ///   需保证唤醒机制和锁释放顺序正确避免死锁。
    fn waiting(&self, pi: usize, addr: usize) -> Result<usize, ()> {
        let mut parent_map = self.parents.lock();
        let p = unsafe { CPU_MANAGER.my_proc() };
        let pdata = unsafe { p.data.get().as_mut().unwrap() };

        loop {
            let mut have_child = false;
            for i in 0..NPROC {
                if parent_map[i].is_none() || *parent_map[i].as_ref().unwrap() != pi {
                    continue;
                }

                let mut child_excl = self.table[i].excl.lock();
                have_child = true;
                if child_excl.state != ProcState::ZOMBIE {
                    continue;
                }
                let child_pid = child_excl.pid;
                if addr != 0 && pdata.copy_out(&child_excl.exit_status as *const _ as *const u8,
                    addr, mem::size_of_val(&child_excl.exit_status)).is_err()
                {
                    return Err(())
                }
                parent_map[i].take();
                self.table[i].killed.store(false, Ordering::Relaxed);
                let child_data = unsafe { self.table[i].data.get().as_mut().unwrap() };
                child_data.cleanup();
                child_excl.cleanup();           
                return Ok(child_pid)
            }

            if !have_child || p.killed.load(Ordering::Relaxed) {
                return Err(())
            }

            // have children, but none of them exit
            let channel = p as *const Proc as usize;
            p.sleep(channel, parent_map);
            parent_map = self.parents.lock();
        }
    }

    /// # 功能说明
    ///
    /// 根据给定的进程标识符（PID）杀死对应的进程。
    /// 查找进程表中匹配的进程，将其 `killed` 标记置为 `true`，
    /// 如果该进程处于 `SLEEPING` 状态，则将其状态改为 `RUNNABLE`，
    /// 以便尽快响应终止请求。
    ///
    /// # 参数
    ///
    /// - `&self`：进程管理器的不可变引用，用于访问进程表。
    /// - `pid: usize`：要杀死的进程的 PID。
    ///
    /// # 返回值
    ///
    /// - `Ok(())` 表示成功找到并标记了该进程为被杀死。
    /// - `Err(())` 表示未找到指定 PID 的进程。
    ///
    /// # 可能的错误
    ///
    /// - 如果传入的 PID 不存在，函数返回错误。
    ///
    /// # 安全性
    ///
    /// - 函数通过进程的自旋锁 `excl` 保护对进程状态的修改，保证并发安全。
    /// - 标记进程为被杀死后，依赖其他机制（如调度器或系统调用）
    ///   处理后续清理和终止动作。
    pub fn kill(&self, pid: usize) -> Result<(), ()> {
        for i in 0..NPROC {
            let mut guard = self.table[i].excl.lock();
            if guard.pid == pid {
                self.table[i].killed.store(true, Ordering::Relaxed);
                if guard.state == ProcState::SLEEPING {
                    guard.state = ProcState::RUNNABLE;
                }
                return Ok(())
            }
        }

        Err(())
    }
}

/// fork 创建的子进程首次被调度器调度时，
/// 会切换到 forkret 函数执行。
/// 需要小心处理，因为 CPU 会使用返回地址寄存器（ra）跳转到这里。
///
/// 安全性说明1：该函数应仅由第一个用户进程调用，
/// 之后其他用户进程可以并发调用 fork_ret。
/// 安全性说明2：该函数是非可重入的，
/// 中断或异常处理程序不得调用此函数。
unsafe fn fork_ret() -> ! {
    static mut INITIALIZED: bool = false;
    
    // Still holding p->lock from scheduler
    CPU_MANAGER.my_proc().excl.unlock();
    
    if !INITIALIZED {
        INITIALIZED = true;
        // File system initialization
        fs::init(ROOTDEV);
    }

    user_trap_ret();
}

/// # 功能说明
///
/// 根据进程索引 `pos` 计算该进程的内核栈虚拟地址起始位置。
/// 内核栈在虚拟地址空间中按顺序从高地址向低地址分配，
/// 每个进程分配连续的 5 页空间（包含实际栈页和保护页）。
/// 该函数返回内核栈的最高地址（栈顶）虚拟地址，用于内核栈映射和访问。
///
/// # 参数
///
/// - `pos: usize`：进程在进程表中的索引，用于计算内核栈偏移。
///
/// # 返回值
///
/// - 返回 `usize` 类型的虚拟地址，表示对应进程内核栈的起始地址（栈顶地址）。
#[inline]
fn kstack(pos: usize) -> usize {
    Into::<usize>::into(TRAMPOLINE) - (pos + 1) * 5 * PGSIZE
}
