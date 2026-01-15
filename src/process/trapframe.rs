/// 用户进程的陷阱帧（Trap Frame）
///
/// 该结构体保存用户态程序在发生陷阱（系统调用、中断、异常）时的 CPU 寄存器上下文，
/// 用于内核在进入和返回用户态时保存和恢复用户进程状态。
/// 
/// 在上下文切换、异常处理及系统调用处理中，
/// 内核通过此结构体存储和恢复用户程序的执行现场，
/// 保证用户程序能够正确继续执行。
#[repr(C)]
#[derive(Debug)]
pub struct TrapFrame {
    /// 内核页表的物理页目录基址 (SATP寄存器值)
    /*   0 */ pub kernel_satp: usize,   // kernel page table

    /// 进程内核栈的栈顶虚拟地址
    /*   8 */ pub kernel_sp: usize,     // top of process's kernel stack
    
    /// 内核陷阱处理函数地址（如 `usertrap`）
    /*  16 */ pub kernel_trap: usize,   // usertrap()
    
    /// 用户程序计数器（程序执行到的下一条指令地址）
    /*  24 */ pub epc: usize,           // saved user program counter
    
    /// 内核线程指针寄存器（`tp`），保存当前 CPU ID
    /*  32 */ pub kernel_hartid: usize, // saved kernel tp
    
    /// 返回地址寄存器（`ra`）
    /*  40 */ pub ra: usize,
    
    /// 栈指针寄存器（`sp`）
    /*  48 */ pub sp: usize,
    
    /// 全局指针寄存器（`gp`）
    /*  56 */ pub gp: usize,
    
    /// 线程指针寄存器（`tp`）
    /*  64 */ pub tp: usize,
    /*  72 */ pub t0: usize,
    /*  80 */ pub t1: usize,
    /*  88 */ pub t2: usize,
    /*  96 */ pub s0: usize,
    /* 104 */ pub s1: usize,
    /* 112 */ pub a0: usize,
    /* 120 */ pub a1: usize,
    /* 128 */ pub a2: usize,
    /* 136 */ pub a3: usize,
    /* 144 */ pub a4: usize,
    /* 152 */ pub a5: usize,
    /* 160 */ pub a6: usize,
    /* 168 */ pub a7: usize,
    /* 176 */ pub s2: usize,
    /* 184 */ pub s3: usize,
    /* 192 */ pub s4: usize,
    /* 200 */ pub s5: usize,
    /* 208 */ pub s6: usize,
    /* 216 */ pub s7: usize,
    /* 224 */ pub s8: usize,
    /* 232 */ pub s9: usize,
    /* 240 */ pub s10: usize,
    /* 248 */ pub s11: usize,
    /* 256 */ pub t3: usize,
    /* 264 */ pub t4: usize,
    /* 272 */ pub t5: usize,
    /* 280 */ pub t6: usize,
}

impl TrapFrame {
    #[inline]
    pub fn admit_ecall(&mut self) {
        self.epc += 4;
    }
}
