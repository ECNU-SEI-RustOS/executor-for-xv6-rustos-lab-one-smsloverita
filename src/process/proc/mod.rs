use array_macro::array;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::mem;
use core::sync::atomic::{AtomicBool, Ordering};
use core::option::Option;
use core::ptr;
use core::cell::UnsafeCell;

use crate::consts::{PGSIZE, fs::{NFILE, ROOTIPATH}};
use crate::mm::{PageTable, RawPage, RawSinglePage};
use crate::register::{satp, sepc, sstatus};
use crate::spinlock::{SpinLock, SpinLockGuard};
use crate::trap::user_trap;
use crate::fs::{Inode, ICACHE, LOG, File};

use super::CpuManager;
use super::PROC_MANAGER;
use super::cpu::CPU_MANAGER;
use super::{fork_ret, Context, TrapFrame};

use self::syscall::Syscall;

mod syscall;
mod elf;

// 【新增】系统调用名称表，用于 Lab 1 trace 打印
static SYSCALL_NAMES: [&str; 23] = [
    "", "fork", "exit", "wait", "pipe", "read", "kill", "exec",
    "fstat", "chdir", "dup", "getpid", "sbrk", "sleep", "uptime",
    "open", "write", "mknod", "unlink", "link", "mkdir", "close", "trace",
];

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum ProcState {
    UNUSED,
    SLEEPING,
    RUNNABLE,
    RUNNING,
    ALLOCATED,
    ZOMBIE,
}

pub struct ProcExcl {
    pub state: ProcState,
    pub exit_status: i32,
    pub channel: usize,
    pub pid: usize,
}

impl ProcExcl {
    const fn new() -> Self {
        Self {
            state: ProcState::UNUSED,
            exit_status: 0,
            channel: 0,
            pid: 0,
        }
    }

    pub fn cleanup(&mut self) {
        self.pid = 0;
        self.channel = 0;
        self.exit_status = 0;
        self.state = ProcState::UNUSED;
    }
}

pub struct ProcData {
    kstack: usize,
    sz: usize,
    context: Context,
    name: [u8; 16],
    open_files: [Option<Arc<File>>; NFILE],
    pub tf: *mut TrapFrame,
    pub pagetable: Option<Box<PageTable>>,
    pub cwd: Option<Inode>,
}

impl ProcData {
    const fn new() -> Self {
        Self {
            kstack: 0,
            sz: 0,
            context: Context::new(),
            name: [0; 16],
            open_files: array![_ => None; NFILE],
            tf: ptr::null_mut(),
            pagetable: None,
            cwd: None,
        }
    }

    pub fn set_kstack(&mut self, kstack: usize) {
        self.kstack = kstack;
    }

    pub fn init_context(&mut self) {
        self.context.clear();
        self.context.set_ra(fork_ret as *const () as usize);
        self.context.set_sp(self.kstack + PGSIZE*4);
    }

    pub fn get_context(&mut self) -> *mut Context {
        &mut self.context as *mut _
    }

    pub fn user_ret_prepare(&mut self) -> usize {
        let tf: &mut TrapFrame = unsafe { self.tf.as_mut().unwrap() };
        tf.kernel_satp = satp::read();
        tf.kernel_sp = self.kstack + PGSIZE*4;
        tf.kernel_trap = user_trap as usize;
        tf.kernel_hartid = unsafe { CpuManager::cpu_id() };
        sepc::write(tf.epc);
        self.pagetable.as_ref().unwrap().as_satp()
    }

    fn check_user_addr(&self, user_addr: usize) -> Result<(), ()> {
        if user_addr > self.sz {
            Err(())
        } else {
            Ok(())
        }
    }

    #[inline]
    pub fn copy_out(&mut self, src: *const u8, dst: usize, count: usize) -> Result<(), ()> {
        self.pagetable.as_mut().unwrap().copy_out(src, dst, count)
    }

    #[inline]
    pub fn copy_in(&self, src: usize, dst: *mut u8, count: usize) -> Result<(), ()> {
        self.pagetable.as_ref().unwrap().copy_in(src, dst, count)
    }

    fn alloc_fd(&mut self) -> Option<usize> {
        self.open_files.iter()
            .enumerate()
            .find(|(_, f)| f.is_none())
            .map(|(i, _)| i)
    }

    fn alloc_fd2(&mut self) -> Option<(usize, usize)> {
        let mut iter = self.open_files.iter()
            .enumerate()
            .filter(|(_, f)| f.is_none())
            .take(2)
            .map(|(i, _)| i);
        let fd1 = iter.next()?;
        let fd2 = iter.next()?;
        Some((fd1, fd2))
    }

    pub fn cleanup(&mut self) {
        self.name[0] = 0;
        let tf = self.tf;
        self.tf = ptr::null_mut();
        if !tf.is_null() {
            unsafe { RawSinglePage::from_raw_and_drop(tf as *mut u8); }
        }
        let pgt = self.pagetable.take();
        if let Some(mut pgt) = pgt {
            pgt.dealloc_proc_pagetable(self.sz);
        }
        self.sz = 0;
    }

    pub fn close_files(&mut self) {
        for f in self.open_files.iter_mut() {
            drop(f.take())
        }
        LOG.begin_op();
        debug_assert!(self.cwd.is_some());
        drop(self.cwd.take());
        LOG.end_op();
    }

    fn sbrk(&mut self, increment: i32) -> Result<usize, ()> {
        let old_size = self.sz;
        if increment > 0 {
            let new_size = old_size + (increment as usize);
            self.pagetable.as_mut().unwrap().uvm_alloc(old_size, new_size)?;
            self.sz = new_size;
        } else if increment < 0 {
            let new_size = old_size - ((-increment) as usize);
            self.pagetable.as_mut().unwrap().uvm_dealloc(old_size, new_size);
            self.sz = new_size;
        }
        Ok(old_size)
    }
}

pub struct Proc {
    index: usize,
    // 【修改 1】新增 trace_mask 字段
    pub trace_mask: i32,
    pub excl: SpinLock<ProcExcl>,
    pub data: UnsafeCell<ProcData>,
    pub killed: AtomicBool,
}

impl Proc {
    pub const fn new(index: usize) -> Self {
        Self {
            index,
            // 【修改 2】初始化 trace_mask
            trace_mask: 0,
            excl: SpinLock::new(ProcExcl::new(), "ProcExcl"),
            data: UnsafeCell::new(ProcData::new()),
            killed: AtomicBool::new(false),
        }
    }

    pub fn user_init(&mut self) {
        let pd = self.data.get_mut();
        pd.pagetable.as_mut().unwrap().uvm_init(&INITCODE);
        pd.sz = PGSIZE;
        let tf = unsafe { pd.tf.as_mut().unwrap() };
        tf.epc = 0;
        tf.sp = PGSIZE;
        let init_name = b"initcode\0";
        unsafe {
            ptr::copy_nonoverlapping(
                init_name.as_ptr(), 
                pd.name.as_mut_ptr(),
                init_name.len()
            );
        }
        debug_assert!(pd.cwd.is_none());
        pd.cwd = Some(ICACHE.namei(&ROOTIPATH).expect("cannot find root inode by b'/'"));
    }

    pub fn check_abondon(&mut self, exit_status: i32) {
        if self.killed.load(Ordering::Relaxed) {
            unsafe { PROC_MANAGER.exiting(self.index, exit_status); }
        }
    }

    pub fn abondon(&mut self, exit_status: i32) {
        self.killed.store(true, Ordering::Relaxed);
        unsafe { PROC_MANAGER.exiting(self.index, exit_status); }
    }

    // 【修改 4】完整的 syscall 实现，包含 trace 注册和打印逻辑
    pub fn syscall(&mut self) {
        sstatus::intr_on();

        let tf = unsafe { self.data.get_mut().tf.as_mut().unwrap() };
        let a7 = tf.a7;
        tf.admit_ecall();
        let sys_result = match a7 {
            1 => self.sys_fork(),
            2 => self.sys_exit(),
            3 => self.sys_wait(),
            4 => self.sys_pipe(),
            5 => self.sys_read(),
            6 => self.sys_kill(),
            7 => self.sys_exec(),
            8 => self.sys_fstat(),
            9 => self.sys_chdir(),
            10 => self.sys_dup(),
            11 => self.sys_getpid(),
            12 => self.sys_sbrk(),
            13 => self.sys_sleep(),
            14 => self.sys_uptime(),
            15 => self.sys_open(),
            16 => self.sys_write(),
            17 => self.sys_mknod(),
            18 => self.sys_unlink(),
            19 => self.sys_link(),
            20 => self.sys_mkdir(),
            21 => self.sys_close(),
            22 => self.sys_trace(), // 注册 trace
            _ => {
                panic!("unknown syscall num: {}", a7);
            }
        };
        tf.a0 = match sys_result {
            Ok(ret) => ret,
            Err(()) => -1isize as usize,
        };

        // 打印逻辑
        if (self.trace_mask >> a7) & 1 != 0 {
            let pid = self.excl.lock().pid;
            let syscall_name = if a7 < SYSCALL_NAMES.len() {
                SYSCALL_NAMES[a7]
            } else {
                "unknown"
            };
            println!("{}: syscall {} -> {}", pid, syscall_name, tf.a0 as isize);
        }
    }

    pub fn yielding(&mut self) {
        let mut guard = self.excl.lock();
        assert_eq!(guard.state, ProcState::RUNNING);
        guard.state = ProcState::RUNNABLE;
        guard = unsafe { CPU_MANAGER.my_cpu_mut().sched(guard,
            self.data.get_mut().get_context()) };
        drop(guard);
    }

    pub fn sleep<T>(&self, channel: usize, guard: SpinLockGuard<'_, T>) {
        let mut excl_guard = self.excl.lock();
        drop(guard);
        excl_guard.channel = channel;
        excl_guard.state = ProcState::SLEEPING;
        unsafe {
            let c = CPU_MANAGER.my_cpu_mut();
            excl_guard = c.sched(excl_guard, 
                &mut (*self.data.get()).context as *mut _);
        }
        excl_guard.channel = 0;
        drop(excl_guard);
    }

    fn fork(&mut self) -> Result<usize, ()> {
        let pdata = self.data.get_mut();
        let child = unsafe { PROC_MANAGER.alloc_proc().ok_or(())? };
        let mut cexcl = child.excl.lock();
        let cdata = unsafe { child.data.get().as_mut().unwrap() };

        let cpgt = cdata.pagetable.as_mut().unwrap();
        let size = pdata.sz;
        if pdata.pagetable.as_mut().unwrap().uvm_copy(cpgt, size).is_err() {
            debug_assert_eq!(child.killed.load(Ordering::Relaxed), false);
            child.killed.store(false, Ordering::Relaxed);
            cdata.cleanup();
            cexcl.cleanup();
            return Err(())
        }
        cdata.sz = size;

        unsafe {
            ptr::copy_nonoverlapping(pdata.tf, cdata.tf, 1);
            cdata.tf.as_mut().unwrap().a0 = 0;
        }

        cdata.open_files.clone_from(&pdata.open_files);
        cdata.cwd.clone_from(&pdata.cwd);
        cdata.name.copy_from_slice(&pdata.name);

        let cpid = cexcl.pid;
        drop(cexcl);

        // 【修改 3】继承 trace_mask
        child.trace_mask = self.trace_mask;

        unsafe { PROC_MANAGER.set_parent(child.index, self.index); }

        let mut cexcl = child.excl.lock();
        cexcl.state = ProcState::RUNNABLE;
        drop(cexcl);

        Ok(cpid)
    }

    fn arg_raw(&self, n: usize) -> usize {
        let tf = unsafe { self.data.get().as_ref().unwrap().tf.as_ref().unwrap() };
        match n {
            0 => {tf.a0}
            1 => {tf.a1}
            2 => {tf.a2}
            3 => {tf.a3}
            4 => {tf.a4}
            5 => {tf.a5}
            _ => { panic!("n is larger than 5") }
        }
    }

    #[inline]
    fn arg_i32(&self, n: usize) -> i32 {
        self.arg_raw(n) as i32
    }

    #[inline]
    fn arg_addr(&self, n: usize) -> usize {
        self.arg_raw(n)
    }

    #[inline]
    fn arg_fd(&mut self, n: usize) -> Result<usize, ()> {
        let fd = self.arg_raw(n);
        if fd >= NFILE || self.data.get_mut().open_files[fd].is_none() {
            Err(())
        } else {
            Ok(fd)
        }
    }

    fn arg_str(&self, n: usize, buf: &mut [u8]) -> Result<(), &'static str> {
        let addr: usize = self.arg_raw(n);
        let pagetable = unsafe { self.data.get().as_ref().unwrap().pagetable.as_ref().unwrap() };
        pagetable.copy_in_str(addr, buf)?;
        Ok(())
    }

    fn fetch_addr(&self, addr: usize) -> Result<usize, &'static str> {
        let pd = unsafe { self.data.get().as_ref().unwrap() };
        if addr + mem::size_of::<usize>() > pd.sz {
            Err("input addr > proc's mem size")
        } else {
            let mut ret: usize = 0;
            match pd.copy_in(
                addr, 
                &mut ret as *mut usize as *mut u8, 
                mem::size_of::<usize>()
            ) {
                Ok(_) => Ok(ret),
                Err(_) => Err("pagetable copy_in eror"),
            }
        }
    }

    fn fetch_str(&self, addr: usize, dst: &mut [u8]) -> Result<(), &'static str>{
        let pd = unsafe { self.data.get().as_ref().unwrap() };
        pd.pagetable.as_ref().unwrap().copy_in_str(addr, dst)
    }
}

static INITCODE: [u8; 51] = [
    0x17, 0x05, 0x00, 0x00, 0x13, 0x05, 0x05, 0x02, 0x97, 0x05, 0x00, 0x00, 0x93, 0x85, 0x05, 0x02,
    0x9d, 0x48, 0x73, 0x00, 0x00, 0x00, 0x89, 0x48, 0x73, 0x00, 0x00, 0x00, 0xef, 0xf0, 0xbf, 0xff,
    0x2f, 0x69, 0x6e, 0x69, 0x74, 0x00, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
];