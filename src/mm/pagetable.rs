use array_macro::array;

use alloc::boxed::Box;
use core::{cmp::min, convert::TryFrom};
use core::ptr;

use crate::consts::{PGSHIFT, PGSIZE, SATP_SV39, SV39FLAGLEN, USERTEXT, TRAMPOLINE, TRAPFRAME};
use super::{Addr, PhysAddr, RawPage, RawSinglePage, VirtAddr, pg_round_up};

bitflags! {
    pub struct PteFlag: usize {
        const V = 1 << 0;
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const A = 1 << 6;
        const D = 1 << 7;
        const RSW = 0b11 << 8;
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PageTableEntry {
    data: usize,
}

impl PageTableEntry {
    #[inline]
    pub fn is_valid(&self) -> bool {
        (self.data & (PteFlag::V.bits())) > 0
    }

    #[inline]
    fn is_leaf(&self) -> bool {
        let flag_bits = self.data & (PteFlag::R|PteFlag::W|PteFlag::X).bits();
        !(flag_bits == 0)
    }

    #[inline]
    fn is_user(&self) -> bool {
        (self.data & (PteFlag::U.bits())) > 0
    }

    #[inline]
    fn clear_user(&mut self) {
        self.data &= !PteFlag::U.bits()
    }

    #[inline]
    fn as_page_table(&self) -> *mut PageTable {
        ((self.data >> SV39FLAGLEN) << PGSHIFT) as *mut PageTable
    }

    #[inline]
    pub fn as_phys_addr(&self) -> PhysAddr {
        unsafe { PhysAddr::from_raw((self.data >> SV39FLAGLEN) << PGSHIFT) }
    }

    #[inline]
    fn write_zero(&mut self) {
        self.data = 0;
    }

    #[inline]
    fn write(&mut self, pa: PhysAddr) {
        self.data = ((pa.as_usize() >> PGSHIFT) << SV39FLAGLEN) | (PteFlag::V.bits());
    }

    #[inline]
    fn write_perm(&mut self, pa: PhysAddr, perm: PteFlag) {
        self.data = ((pa.as_usize() >> PGSHIFT) << SV39FLAGLEN) | (perm | PteFlag::V).bits()
    }

    #[inline]
    fn read_perm(&self) -> PteFlag {
        PteFlag::from_bits_truncate(self.data)
    }

    unsafe fn try_clone(&self) -> Result<*mut u8, ()> {
        if !self.is_valid() {
            panic!("cloning not valid pte");
        }
        let pa = self.as_phys_addr().into_raw();
        let mem = RawSinglePage::try_new_uninit().map_err(|_| ())?;
        ptr::copy_nonoverlapping(pa as *const u8, mem, PGSIZE);
        Ok(mem)
    }

    fn free(&mut self) {
        if self.is_valid() {
            if !self.is_leaf() {
                drop(unsafe { Box::from_raw(self.as_page_table()) });
                self.data = 0;
            } else {
                panic!("freeing a pte leaf")
            }
        }
    }
}

#[repr(C, align(4096))]
pub struct PageTable {
    data: [PageTableEntry; 512],
}

impl PageTable {
    pub const fn empty() -> Self {
        Self {
            data: array![_ => PageTableEntry { data: 0 }; 512],
        }
    }

    pub fn as_satp(&self) -> usize {
        SATP_SV39 | ((self as *const PageTable as usize) >> PGSHIFT)
    }

    pub fn map_pages(
        &mut self,
        mut va: VirtAddr,
        size: usize,
        mut pa: PhysAddr,
        perm: PteFlag,
    ) -> Result<(), &'static str> {
        let mut last = VirtAddr::try_from(va.as_usize() + size)?;
        va.pg_round_down();
        last.pg_round_up();

        while va != last {
            match self.walk_alloc(va) {
                Some(pte) => {
                    if pte.is_valid() {
                        println!(
                            "va: {:#x}, pa: {:#x}, pte: {:#x}",
                            va.as_usize(),
                            pa.as_usize(),
                            pte.data
                        );
                        panic!("remap");
                    }
                    pte.write_perm(pa, perm);
                    va.add_page();
                    pa.add_page();
                }
                None => {
                    return Err("PageTable.map_pages: \
                    not enough memory for new page table")
                }
            }
        }

        Ok(())
    }

    fn walk_alloc(&mut self, va: VirtAddr) -> Option<&mut PageTableEntry> {
        let mut pgt = self as *mut PageTable;
        for level in (1..=2).rev() {
            let pte = unsafe { &mut pgt.as_mut().unwrap().data[va.page_num(level)] };

            if pte.is_valid() {
                pgt = pte.as_page_table();
            } else {
                let zerod_pgt = unsafe { Box::<Self>::try_new_zeroed().ok()?.assume_init() };
                pgt = Box::into_raw(zerod_pgt);
                pte.write(PhysAddr::try_from(pgt as usize).unwrap());
            }
        }
        unsafe { Some(&mut pgt.as_mut().unwrap().data[va.page_num(0)]) }
    }

    fn walk_mut(&mut self, va: VirtAddr) -> Option<&mut PageTableEntry> {
        let mut pgt = self as *mut PageTable;
        for level in (1..=2).rev() {
            let pte = unsafe { &mut pgt.as_mut().unwrap().data[va.page_num(level)] };

            if pte.is_valid() {
                pgt = pte.as_page_table();
            } else {
                return None
            }
        }
        unsafe { Some(&mut pgt.as_mut().unwrap().data[va.page_num(0)]) }
    }

    pub fn walk(&self, va: VirtAddr) -> Option<&PageTableEntry> {
        let mut pgt = self as *const PageTable;
        for level in (1..=2).rev() {
            let pte = unsafe { &pgt.as_ref().unwrap().data[va.page_num(level)] };

            if pte.is_valid() {
                pgt = pte.as_page_table();
            } else {
                return None
            }
        }
        unsafe { Some(&pgt.as_ref().unwrap().data[va.page_num(0)]) }
    }

    pub fn walk_addr_mut(&mut self, va: VirtAddr)
        -> Result<PhysAddr, &'static str>
    {
        match self.walk_mut(va) {
            Some(pte) => {
                if !pte.is_valid() {
                    Err("pte not valid")
                } else if !pte.is_user() {
                    Err("pte not mapped for user")
                } else {
                    Ok(pte.as_phys_addr())
                }
            }
            None => {
                Err("va not mapped")
            }
        }
    }

    pub fn walk_addr(&self, va: VirtAddr)
        -> Result<PhysAddr, &'static str>
    {
        match self.walk(va) {
            Some(pte) => {
                if !pte.is_valid() {
                    Err("pte not valid")
                } else if !pte.is_user() {
                    Err("pte not mapped for user")
                } else {
                    Ok(pte.as_phys_addr())
                }
            }
            None => {
                Err("va not mapped")
            }
        }
    }

    pub fn alloc_proc_pagetable(trapframe: usize) -> Option<Box<Self>> {
        extern "C" {
            fn trampoline();
        }

        let mut pagetable = unsafe { Box::<Self>::try_new_zeroed().ok()?.assume_init() };
        pagetable
            .map_pages(
                VirtAddr::from(TRAMPOLINE),
                PGSIZE,
                PhysAddr::try_from(trampoline as usize).unwrap(),
                PteFlag::R | PteFlag::X,
            )
            .ok()?;
        pagetable
            .map_pages(
                VirtAddr::from(TRAPFRAME),
                PGSIZE,
                PhysAddr::try_from(trapframe).unwrap(),
                PteFlag::R | PteFlag::W,
            )
            .ok()?;

        Some(pagetable)
    }

    pub fn dealloc_proc_pagetable(&mut self, proc_size: usize) {
        self.uvm_unmap(TRAMPOLINE.into(), 1, false);
        self.uvm_unmap(TRAPFRAME.into(), 1, false);
        // free physical memory
        if proc_size > 0 {
            self.uvm_unmap(0, pg_round_up(proc_size)/PGSIZE, true);
        }
    }

    pub fn uvm_init(&mut self, code: &[u8]) {
        if code.len() >= PGSIZE {
            panic!("initcode more than a page");
        }
 
        let mem = unsafe { RawSinglePage::new_zeroed() as *mut u8 };
        self.map_pages(
            VirtAddr::from(USERTEXT),
            PGSIZE,
            PhysAddr::try_from(mem as usize).unwrap(),
            PteFlag::R | PteFlag::W | PteFlag::X | PteFlag::U)
            .expect("map_page error");
        unsafe { ptr::copy_nonoverlapping(code.as_ptr(), mem, code.len()); }
    }

    pub fn uvm_alloc(&mut self, old_size: usize, new_size: usize) -> Result<usize, ()> {
        if new_size <= old_size {
            return Ok(old_size)
        }

        let old_size = pg_round_up(old_size);
        for cur_size in (old_size..new_size).step_by(PGSIZE) {
            match unsafe { RawSinglePage::try_new_zeroed() } {
                Err(_) => {
                    self.uvm_dealloc(cur_size, old_size);
                    return Err(())
                },
                Ok(mem) => {
                    match self.map_pages(
                        unsafe { VirtAddr::from_raw(cur_size) },
                        PGSIZE, 
                        unsafe { PhysAddr::from_raw(mem as usize) }, 
                        PteFlag::R | PteFlag::W | PteFlag::X | PteFlag::U
                    ) {
                        Err(s) => {
                            #[cfg(feature = "kernel_warning")]
                            println!("kernel warning: uvm_alloc occurs {}", s);
                            unsafe { RawSinglePage::from_raw_and_drop(mem); }
                            self.uvm_dealloc(cur_size, old_size);
                            return Err(())
                        },
                        Ok(_) => {
                            // the mem raw pointer is leaked
                            // but recorded in the pagetable at virtual address cur_size
                        },
                    }
                },
            }
        }

        Ok(new_size)
    }

    pub fn uvm_dealloc(&mut self, old_size: usize, new_size: usize) -> usize {
        if new_size >= old_size {
            return old_size
        }

        let old_size_aligned = pg_round_up(old_size);
        let new_size_aligned = pg_round_up(new_size);
        if new_size_aligned < old_size_aligned {
            let count = (old_size_aligned - new_size_aligned) / PGSIZE;
            self.uvm_unmap(new_size_aligned, count, true);
        }

        new_size
    }

    pub fn uvm_unmap(&mut self, va: usize, count: usize, freeing: bool) {
        if va % PGSIZE != 0 {
            panic!("va not page aligned");
        }

        for ca in (va..(va+PGSIZE*count)).step_by(PGSIZE) {
            let pte = self.walk_mut(unsafe {VirtAddr::from_raw(ca)})
                                        .expect("unable to find va available");
            if !pte.is_valid() {
                panic!("this pte is not valid");
            }
            if !pte.is_leaf() {
                panic!("this pte is not a leaf");
            }
            if freeing {
                let pa = pte.as_phys_addr();
                unsafe { RawSinglePage::from_raw_and_drop(pa.into_raw() as *mut u8); }
            }
            pte.write_zero();
        }
    }

    pub fn uvm_clear(&mut self, va: usize) {
        let pte = self.walk_mut(VirtAddr::try_from(va).unwrap())
                                                .expect("cannot find available pte");
        pte.clear_user();
    }

    pub fn uvm_copy(&mut self, child_pgt: &mut Self, size: usize) -> Result<(), ()> {
        for i in (0..size).step_by(PGSIZE) {
            let va = unsafe { VirtAddr::from_raw(i) };
            let pte = self.walk(va).expect("pte not exist");
            let mem = unsafe { pte.try_clone() };
            if let Ok(mem) = mem {
                let perm = pte.read_perm();
                if child_pgt.map_pages(va, PGSIZE,
                    unsafe { PhysAddr::from_raw(mem as usize) }, perm).is_ok()
                {
                    continue
                }
                unsafe { RawSinglePage::from_raw_and_drop(mem); }
            }
            child_pgt.uvm_unmap(0, i/PGSIZE, true);
            return Err(())
        }
        Ok(())
    }

    pub fn copy_in_str(&self, srcva: usize, dst: &mut [u8])
        -> Result<(), &'static str>
    {
        let mut i: usize = 0;
        let mut va = VirtAddr::try_from(srcva)?;

        // iterate through the raw content page by page
        while i < dst.len() {
            let mut base = va;
            base.pg_round_down();
            let distance = (va - base).as_usize();
            let mut pa_ptr = unsafe {
                self.walk_addr(base)?
                    .as_ptr()
                    .offset(distance as isize)
            };
            let mut va_ptr = va.as_ptr();
            
            // iterate througn each u8 in a page
            let mut count = min(PGSIZE - distance, dst.len() - i);
            while count > 0 {
                unsafe {
                    dst[i] = ptr::read(pa_ptr);
                    if dst[i] == 0 {
                        return Ok(())
                    }
                    i += 1;
                    count -= 1;
                    pa_ptr = pa_ptr.add(1);
                    va_ptr = va_ptr.add(1);
                }
            }

            base.add_page();
            va = base;
        }

        Err("copy_in_str: dst not enough space")
    }

    pub fn copy_out(&mut self, mut src: *const u8, mut dst: usize, mut count: usize)
        -> Result<(), ()>
    {
        if count == 0 {
            return Ok(())
        }

        let mut va = VirtAddr::try_from(dst).map_err(|_| ())?;
        va.pg_round_down();
        loop {
            let mut pa;
            match self.walk_addr_mut(va) {
                Ok(phys_addr) => pa = phys_addr,
                Err(s) => {
                    #[cfg(feature = "kernel_warning")]
                    println!("kernel warning: {} when pagetable copy_out", s);
                    return Err(())
                }
            }
            let off = dst - va.as_usize();
            let off_from_end = PGSIZE - off;
            let off = off as isize;
            let dst_ptr = unsafe { pa.as_mut_ptr().offset(off) };
            if off_from_end > count {
                unsafe { ptr::copy(src, dst_ptr, count); }
                return Ok(())
            }
            unsafe { ptr::copy(src, dst_ptr, off_from_end); }
            count -= off_from_end;
            src = unsafe { src.offset(off_from_end as isize) };
            dst += off_from_end;
            va.add_page();
            debug_assert_eq!(dst, va.as_usize());
        }
    }

    pub fn copy_in(&self, mut src: usize, mut dst: *mut u8, mut count: usize)
        -> Result<(), ()>
    {
        let mut va = VirtAddr::try_from(src).unwrap();
        va.pg_round_down();

        if count == 0 {
            match self.walk_addr(va) {
                Ok(_) => return Ok(()),
                Err(s) => {
                    #[cfg(feature = "kernel_warning")]
                    println!("kernel warning: {} when pagetable copy_in", s);
                    return Err(())
                }
            }
        }

        loop {
            let pa;
            match self.walk_addr(va) {
                Ok(phys_addr) => pa = phys_addr,
                Err(s) => {
                    #[cfg(feature = "kernel_warning")]
                    println!("kernel warning: {} when pagetable copy_in", s);
                    return Err(())
                }
            }
            let off = src - va.as_usize();
            let off_from_end = PGSIZE - off;
            let off = off as isize;
            let src_ptr = unsafe { pa.as_ptr().offset(off) };
            if off_from_end > count {
                unsafe { ptr::copy(src_ptr, dst, count); }
                return Ok(())
            }
            unsafe { ptr::copy(src_ptr, dst, off_from_end); }
            count -= off_from_end;
            src += off_from_end;
            dst = unsafe { dst.offset(off_from_end as isize) };
            va.add_page();
            debug_assert_eq!(src, va.as_usize());
        }
    }

    // 【附加题】vm_print 的正确实现
    pub fn vm_print(&self, depth: usize) {
        // 1. 打印表头 (仅在最顶层)
        if depth == 0 {
            println!("page table {:#x}", self as *const _ as usize);
        }

        // 2. 遍历页表项
        for (i, pte) in self.data.iter().enumerate() {
            if pte.is_valid() {
                // 3. 打印缩进
                for _ in 0..=depth {
                    print!("..");
                }
                
                // 4. 计算物理地址
                let pa = pte.as_phys_addr().as_usize();
                
                // 5. 打印详情
                println!("{}: pte {:#x} pa {:#x}", i, pte.data, pa);

                // 6. 递归条件
                if !pte.is_leaf() && depth < 2 {
                    let child_ptr = pte.as_page_table();
                    let child_pt = unsafe { &*child_ptr };
                    child_pt.vm_print(depth + 1);
                }
            }
        }
    }
}

impl Drop for PageTable {
    fn drop(&mut self) {
        self.data.iter_mut().for_each(|pte| pte.free());
    }
}