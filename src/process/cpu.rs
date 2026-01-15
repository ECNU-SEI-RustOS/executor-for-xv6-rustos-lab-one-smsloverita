use array_macro::array;

use core::ptr;

use crate::register::{tp, sstatus};
use crate::spinlock::SpinLockGuard;
use crate::consts::NCPU;
use super::{Context, PROC_MANAGER, Proc, ProcState, proc::ProcExcl};

/// 全局 CPU 管理器实例
///
/// `CPU_MANAGER` 是一个静态可变变量，代表整个系统中所有 CPU（hart）的管理结构。
/// 它持有一个固定大小的数组，数组中每个元素是一个 `Cpu` 结构体，分别对应系统中的每个 CPU 核心。
///
/// 该结构用于管理每个 CPU 上当前运行的进程、调度上下文等信息，
/// 并提供了获取当前 CPU 相关数据的接口，以及核心调度逻辑。
///
/// 由于操作涉及多核并发和低级硬件操作，为避免竞态条件，访问该变量时需保证中断关闭（或其他同步机制），
/// 并且在很多方法中使用了 `unsafe`，调用者需谨慎确保安全性。
///
/// 该变量的生命周期贯穿整个系统运行期间，是核心的 CPU 状态管理全局入口。
pub static mut CPU_MANAGER: CpuManager = CpuManager::new();

/// CPU 管理器，维护系统中所有 CPU 核心的状态信息。
///
/// `CpuManager` 通过固定大小数组 `table` 存储每个 CPU 对应的 `Cpu` 结构体，
/// 用于跟踪每个 CPU 的运行状态、调度上下文以及当前运行的进程。
/// 
/// 该结构是多核系统调度的核心组件，负责协调不同 CPU 之间的进程调度。
/// 访问和修改时通常需要关闭中断或使用同步机制以避免竞态。
///
pub struct CpuManager {
    /// 所有 CPU 核心状态的数组，长度为系统支持的最大 CPU 数量 `NCPU`。
    /// 每个元素对应一个 CPU 核心，包含该 CPU 的运行进程和调度上下文。
    table: [Cpu; NCPU]
}

impl CpuManager {
    const fn new() -> Self {
        Self {
            table: array![_ => Cpu::new(); NCPU],
        }
    }

    /// Must be called with interrupts disabled,
    /// to prevent race with process being moved
    /// to a different CPU.
    #[inline]
    pub unsafe fn cpu_id() -> usize {
        tp::read()
    }

    /// Return the reference this CPU's cpu struct.
    /// Interrupts must be disabled.
    unsafe fn my_cpu(&self) -> &Cpu {
        let id = Self::cpu_id();
        &self.table[id]
    }

    /// Return the mutable reference this CPU's cpu struct.
    /// Interrupts must be disabled.
    pub unsafe fn my_cpu_mut(&mut self) -> &mut Cpu {
        let id = Self::cpu_id();
        &mut self.table[id]
    }

    /// # 功能说明
    /// 获取当前 CPU 上正在运行的进程的可变引用。
    /// 该方法可以在多核系统中被不同 CPU 同时调用，
    /// 用于访问当前 CPU 所调度的进程。
    ///
    /// # 参数
    /// - `&self`：`CpuManager` 的不可变引用。
    ///
    /// # 返回值
    /// 返回当前 CPU 上运行的进程的可变引用 `&mut Proc`。
    ///
    /// # 可能的错误
    /// - 如果当前 CPU 上没有运行的进程（`proc` 指针为空），
    ///   则会触发 panic。
    ///
    /// # 安全性
    /// - 函数内部调用了 `push_off()` 和 `pop_off()` 来关闭和恢复中断，
    ///   以防止在访问过程中发生竞态条件。
    /// - 使用了 `unsafe` 代码从裸指针转换为可变引用，
    ///   调用者必须保证当前 CPU 的 `proc` 指针有效且唯一持有，
    ///   否则可能导致数据竞争或未定义行为。
    /// - 由于返回了可变引用，必须确保调用者不会引入别名可变引用。
    pub fn my_proc(&self) -> &mut Proc {
        let p;
        push_off();
        unsafe {
            let c = self.my_cpu();
            if c.proc.is_null() {
                panic!("my_proc(): no process running");
            }
            p = &mut *c.proc;
        }
        pop_off();
        p
    }

    /// # 功能说明
    /// CPU 调度器主循环，实现多核环境下对进程的抢占式调度。
    /// 该函数从进程管理器中选择一个可运行进程，进行上下文切换，
    /// 在当前 CPU 上运行选中的进程。调度器永不返回，
    /// 通过循环不断调度进程执行。
    ///
    /// # 流程解释
    /// 1. 调用 `my_cpu_mut()` 获取当前 CPU 的可变引用。
    /// 2. 进入无限循环，确保设备中断打开以允许硬件中断响应。
    /// 3. 通过 `PROC_MANAGER.alloc_runnable()` 尝试获取一个可运行的进程。
    ///    - 若成功，设置当前 CPU 的 `proc` 指针指向该进程。
    ///    - 获取该进程的排他锁，修改进程状态为 `RUNNING`。
    ///    - 调用外部汇编函数 `swtch`，完成从调度器上下文切换到进程上下文。
    ///    - 上下文切换返回后，检查 `proc` 是否为空，
    ///      若为空则触发 panic，说明调度异常。
    ///    - 清空 `proc` 指针，释放进程锁。
    /// 4. 若无可运行进程，继续循环等待。
    ///
    /// # 参数
    /// - `&mut self`：`CpuManager` 的可变引用，允许修改 CPU 相关状态。
    ///
    /// # 返回值
    /// 永不返回（`!`），该函数以无限循环形式持续执行调度。
    ///
    /// # 可能的错误
    /// - 如果上下文切换返回时 `c.proc` 为空，表示调度状态异常，
    ///   触发 panic。
    /// - 使用裸指针和 `unsafe` 代码，若上下文切换实现不正确，
    ///   可能导致未定义行为。
    ///
    /// # 安全性
    /// - 该函数为 `unsafe`，调用时必须保证当前 CPU 和进程状态的正确初始化，
    ///   并且调用环境无竞态。
    /// - 调用期间中断被开启以响应外部事件，需确保中断处理正确。
    /// - 上下文切换依赖外部汇编函数 `swtch`，要求其正确保存和恢复寄存器状态。
    /// - 进程的排他锁在调度期间被持有，防止进程状态并发修改。
    ///
    pub unsafe fn scheduler(&mut self) -> ! {
        extern "C" {
            fn swtch(old: *mut Context, new: *mut Context);
        }

        let c = self.my_cpu_mut();

        loop {
            // ensure devices can interrupt
            sstatus::intr_on();

            // use ProcManager to find a runnable process
            match PROC_MANAGER.alloc_runnable() {
                Some(p) => {
                    c.proc = p as *mut _;
                    let mut guard = p.excl.lock();
                    guard.state = ProcState::RUNNING;

                    swtch(&mut c.scheduler as *mut Context,
                        p.data.get_mut().get_context());
                    
                    if c.proc.is_null() {
                        panic!("context switch back with no process reference");
                    }
                    c.proc = ptr::null_mut();
                    drop(guard);
                },
                None => {},
            }
        }
    }
}

/// CPU 结构体，保存当前 CPU 核心的状态信息。
///
/// `Cpu` 结构体用于跟踪单个 CPU（hart）上的执行状态，
/// 包含当前运行的进程指针、调度上下文，以及中断嵌套计数和中断使能状态。
///
/// 该结构体设计为单核独占访问，不需要额外的锁保护，
/// 只由对应 CPU 核心本地访问，确保访问安全性。
///
pub struct Cpu {
    /// 当前在该 CPU 上运行的进程的裸指针。
    /// 如果没有运行进程，则为 null。
    proc: *mut Proc,

    /// 调度器上下文，用于保存调度器自身的寄存器状态，
    /// 在进程切换时作为切换目标上下文。
    scheduler: Context,

    /// 关闭中断的嵌套计数，表示当前中断被禁止的层数。
    /// 每调用一次 `push_off` 计数加 1，每调用一次 `pop_off` 计数减 1。
    noff: u8,

    /// 中断使能标志，记录关闭中断之前的中断使能状态，
    /// 用于恢复中断使能。
    intena: bool,
}

impl Cpu {
    const fn new() -> Self {
        Self {
            proc: ptr::null_mut(),
            scheduler: Context::new(),
            noff: 0,
            intena: false,
        }
    }

    /// # 功能说明
    /// 从当前运行的进程上下文切换回调度器上下文。
    /// 该函数在切换期间保持进程的锁（`SpinLockGuard`），
    /// 确保进程状态的一致性和并发安全。
    ///
    /// # 流程解释
    /// 1. 检查当前持有的锁是否是进程锁，确保调用前已加锁。
    /// 2. 确认 CPU 当前只持有一个锁（`noff == 1`），防止多锁竞争。
    /// 3. 验证进程状态不是运行中，避免非法调度切换。
    /// 4. 确保中断被禁止，避免调度过程中被中断打断。
    /// 5. 保存当前中断使能状态 `intena`。
    /// 6. 调用外部汇编函数 `swtch`，从传入的进程上下文切换到调度器上下文。
    /// 7. 恢复中断使能状态。
    /// 8. 返回持有的进程锁。
    ///
    /// # 参数
    /// - `&mut self`：当前 CPU 的可变引用。
    /// - `guard`：持有的进程排他锁 `SpinLockGuard`，保证进程状态不被并发修改。
    /// - `ctx`：指向当前进程上下文的裸指针，用于上下文切换。
    ///
    /// # 返回值
    /// 返回传入的进程锁 `SpinLockGuard`，以便调用者继续持有锁。
    ///
    /// # 可能的错误
    /// - 若未持有进程锁，则 panic。
    /// - 若持有多把锁，则 panic。
    /// - 若进程状态为运行中，尝试切换会 panic。
    /// - 若中断未关闭，则 panic。
    ///
    /// # 安全性
    /// - 函数标记为 `unsafe`，调用者必须保证传入的上下文指针有效且指向正确的内存。
    /// - `swtch` 是外部汇编函数，需保证正确保存和恢复寄存器，
    ///   否则可能导致未定义行为。
    /// - 保证函数调用时符合锁和中断状态的前置条件，防止竞态和数据损坏。
    pub unsafe fn sched<'a>(&mut self, guard: SpinLockGuard<'a, ProcExcl>, ctx: *mut Context)
        -> SpinLockGuard<'a, ProcExcl>
    {
        extern "C" {
            fn swtch(old: *mut Context, new: *mut Context);
        }

        // interrupt is off
        if !guard.holding() {
            panic!("sched(): not holding proc's lock");
        }
        // only holding self.proc's lock
        if self.noff != 1 {
            panic!("sched(): cpu hold multi locks");
        }
        // proc is not running
        if guard.state == ProcState::RUNNING {
            panic!("sched(): proc is running");
        }
        // should not be interruptible
        if sstatus::intr_get() {
            panic!("sched(): interruptible");
        }

        let intena = self.intena;
        swtch(ctx, &mut self.scheduler as *mut Context);
        self.intena = intena;

        guard
    }

    /// # 功能说明
    /// 尝试让当前 CPU 上持有的进程主动让出 CPU 执行权（yield）。
    /// 如果当前 CPU 没有进程或进程不处于运行状态，则直接返回。
    ///
    /// # 流程解释
    /// 1. 检查当前 CPU 的 `proc` 指针是否为空，判断是否有进程存在。
    /// 2. 如果存在进程，获取该进程的排他锁 `excl`。
    /// 3. 判断进程状态是否为 `RUNNING`。
    ///    - 若是，释放锁后调用进程的 `yielding()` 方法，触发主动让出。
    ///    - 否则，直接释放锁，函数返回。
    ///
    /// # 参数
    /// - `&mut self`：当前 CPU 的可变引用，用于访问和操作 CPU 状态。
    ///
    /// # 返回值
    /// 无返回值。
    ///
    /// # 可能的错误
    /// - 使用了 `unsafe` 解引用裸指针，若 `proc` 指针无效会导致未定义行为。
    /// - 若进程锁 `excl` 锁定失败，可能阻塞或引发死锁（取决于锁实现）。
    ///
    /// # 安全性
    /// - `unsafe` 用于裸指针解引用，调用者必须保证 `proc` 指针始终有效且唯一。
    /// - 锁机制保证并发安全，避免进程状态被竞态修改。
    ///
    pub fn try_yield_proc(&mut self) {
        if !self.proc.is_null() {
            let guard = unsafe {
                self.proc.as_mut().unwrap().excl.lock()
            };
            if guard.state == ProcState::RUNNING {
                drop(guard);
                unsafe { self.proc.as_mut().unwrap().yielding(); }
            } else {
                drop(guard);
            }
        }
    }
}

/// # 功能说明
/// 关闭当前 CPU 的中断，并记录中断关闭的嵌套次数。
/// 与 `intr_off()` 类似，但支持成对使用，
/// 多次调用 `push_off()` 需要相应次数的 `pop_off()` 才能恢复中断状态。
/// 如果中断原本就是关闭状态，调用后保持关闭。
///
/// # 流程解释
/// 1. 读取当前中断使能状态 `old`。
/// 2. 调用 `sstatus::intr_off()` 关闭中断。
/// 3. 获取当前 CPU 的可变引用 `c`。
/// 4. 若嵌套计数 `noff` 为 0，说明之前中断是开启的，
///    将原始中断状态保存到 `intena`，用于后续恢复。
/// 5. 将嵌套计数 `noff` 自增 1，表示又关闭了一层中断。
///
/// # 参数
/// 无参数。
///
/// # 返回值
/// 无返回值。
///
/// # 可能的错误
/// - 调用时必须保证当前环境已正确初始化 `CPU_MANAGER` 和 CPU 状态，
///   否则 `unsafe` 代码可能引发未定义行为。
///
/// # 安全性
/// - 内部使用了 `unsafe` 获取当前 CPU 的可变引用，
///   调用者需保证不会产生数据竞争。
/// - 通过嵌套计数管理中断关闭层级，避免误操作导致中断状态错乱。
///
pub fn push_off() {
    let old = sstatus::intr_get();
    sstatus::intr_off();
    let c = unsafe { CPU_MANAGER.my_cpu_mut() };
    if c.noff == 0 {
        c.intena = old;
    }
    c.noff += 1;
}

/// # 功能说明
/// 解除之前通过 `push_off()` 关闭的中断，
/// 通过嵌套计数控制中断恢复，
/// 只有所有嵌套的关闭操作都对应调用后，
/// 才真正重新开启中断。
///
/// # 流程解释
/// 1. 检查当前中断状态是否已开启，
///    若是则 panic，表示调用 `pop_off()` 时中断未关闭，逻辑错误。
/// 2. 获取当前 CPU 的可变引用 `c`。
/// 3. 检查中断关闭嵌套计数 `noff` 是否大于 0，
///    若不能减 1，则 panic，表示调用不匹配。
/// 4. 将嵌套计数 `noff` 减 1。
/// 5. 若嵌套计数归零且之前中断为开启状态（`intena == true`），
///    调用 `sstatus::intr_on()` 恢复中断。
///
/// # 参数
/// 无参数。
///
/// # 返回值
/// 无返回值。
///
/// # 可能的错误
/// - 如果在中断已开启时调用，会 panic，
///   防止错误的中断状态恢复。
/// - 如果调用次数与 `push_off()` 不匹配，
///   导致嵌套计数异常，panic 保护。
///
/// # 安全性
/// - 内部使用了 `unsafe` 获取当前 CPU 的可变引用，
///   需要调用者保证不存在数据竞争。
/// - 嵌套计数确保中断状态一致性，防止中断误开启或误关闭。
///
pub fn pop_off() {
    if sstatus::intr_get() {
        panic!("pop_off(): interruptable");
    }
    let c = unsafe { CPU_MANAGER.my_cpu_mut() };
    if c.noff.checked_sub(1).is_none() {
        panic!("pop_off(): count not match");
    }
    c.noff -= 1;
    if c.noff == 0 && c.intena {
        sstatus::intr_on();
    }
}
