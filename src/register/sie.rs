//! sie register

use core::arch::asm;

const SSIE: usize = 1 << 1; // software
const STIE: usize = 1 << 5; // timer
const SEIE: usize = 1 << 9; // external

#[inline]
unsafe fn read() -> usize {
    let ret: usize;
    asm!("csrr {}, sie", out(reg) ret);
    ret
}

#[inline]
unsafe fn write(x: usize) {
    asm!("csrw sie, {}", in(reg) x);
}

/// enable all software interrupts
/// still need to set SIE bit in sstatus
pub unsafe fn intr_on() {
    let mut sie = read();
    sie |= SSIE | STIE | SEIE;
    write(sie);
}
