//! mie register

use core::arch::asm;

use bit_field::BitField;

#[inline]
unsafe fn read() -> usize {
    let ret: usize;
    asm!("csrr {}, mie", out(reg)ret);
    ret
}

#[inline]
unsafe fn write(x: usize) {
    asm!("csrw mie, {}",in(reg)x);
}

/// set MTIE field
pub unsafe fn set_mtie() {
    let mut mie = read();
    mie.set_bit(7, true);
    write(mie);
}
