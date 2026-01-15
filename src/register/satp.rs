//! satp register

use core::arch::asm;

#[inline]
pub fn read() -> usize {
    let ret;
    unsafe {
        asm!("csrr {}, satp", out(reg) ret);
    }
    ret
}

#[inline]
pub fn write(satp: usize) {
    unsafe {
        asm!("csrw satp, {}", in(reg) satp);
    }
}
