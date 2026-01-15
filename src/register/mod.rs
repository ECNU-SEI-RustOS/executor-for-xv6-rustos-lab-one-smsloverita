//! register modules defined in this file are only used once in start.rs

pub mod clint;
pub mod mie;
pub mod mstatus;
pub mod satp;
pub mod sie;
pub mod sip;
pub mod sstatus;
pub mod scause;

/// medeleg
pub mod medeleg {
    pub unsafe fn write(medeleg: usize) {
        core::arch::asm!("csrw medeleg, {}",in(reg)medeleg);
    }
}

/// mepc
pub mod mepc {
    pub unsafe fn write(mepc: usize) {
        core::arch::asm!("csrw mepc, {}", in(reg)mepc);
    }
}

/// mhartid
pub mod mhartid {
    pub unsafe fn read() -> usize {
        let ret: usize;
        core::arch::asm!("csrr {}, mhartid",out(reg)ret);
        ret
    }
}

/// mideleg
pub mod mideleg {
    pub unsafe fn write(mideleg: usize) {
        core::arch::asm!("csrw mideleg, {}", in(reg)mideleg);
    }
}

/// mscratch
pub mod mscratch {
    pub unsafe fn write(mscratch: usize) {
        core::arch::asm!("csrw mscratch, {}",in(reg)mscratch);
    }
}

/// mtvec
pub mod mtvec {
    pub unsafe fn write(mtvec: usize) {
        core::arch::asm!("csrw mtvec, {}",in(reg)mtvec);
    }
}

/// tp
pub mod tp {
    pub unsafe fn read() -> usize {
        let ret: usize;
        core::arch::asm!("mv {}, tp",out(reg)ret);
        ret
    }

    pub unsafe fn write(tp: usize) {
        core::arch::asm!("mv tp, {}", in(reg)tp);
    }
}

/// stvec
pub mod stvec {
    pub unsafe fn write(stvec: usize) {
        core::arch::asm!("csrw stvec, {}", in(reg)stvec);
    }
}

/// sepc
/// machine exception program counter, holds the
/// instruction address to which a return from
/// exception will go.(from xv6-riscv)
pub mod sepc {
    pub fn read() -> usize {
        let ret: usize;
        unsafe {core::arch::asm!("csrr {}, sepc", out(reg)ret);}
        ret
    }

    pub fn write(sepc: usize) {
        unsafe {core::arch::asm!("csrw sepc, {}", in(reg)sepc);}
    }
}

/// stval
/// contains supervisor trap value
pub mod stval {
    pub fn read() -> usize {
        let ret: usize;
        unsafe { core::arch::asm!("csrr {}, stval", out(reg)ret);}
        ret
    }
}
