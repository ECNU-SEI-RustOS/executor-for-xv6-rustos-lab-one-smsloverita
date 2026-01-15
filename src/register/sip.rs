//! Supervisor Interrupt Pending

use core::arch::asm;

const SSIP: usize = 1 << 1;

#[inline]
unsafe fn read() -> usize {
    let ret: usize;
    asm!("csrr {}, sip", out(reg) ret);
    ret
}

#[inline]
unsafe fn write(x: usize) {
    asm!("csrw sip, {}", in(reg) x);
}

pub fn clear_ssip() {
    unsafe {
        write(read() & !SSIP);
    }
}
