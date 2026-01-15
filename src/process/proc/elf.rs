//! ELF loader

use alloc::boxed::Box;
use alloc::str;
use core::{cmp::min, convert::TryFrom, mem::{self, MaybeUninit}};

use crate::{consts::{MAXARGLEN, PGSIZE, MAXARG}, sleeplock::SleepLockGuard};
use crate::mm::{Address, PageTable, Addr, VirtAddr, pg_round_up};
use crate::fs::{ICACHE, Inode, LOG, InodeData};

use super::Proc;

/// 功能说明
/// 该函数用于将指定路径（path）对应的 ELF 可执行文件加载到进程（Proc）的用户空间中，
/// 并将传入的命令行参数（argv）准备好放入用户栈，最终完成进程的内存映射、栈初始化及入口点设置。
///
/// 流程解释
/// 1. 根据给定路径查找并获取对应的文件 inode。
/// 2. 读取 ELF 文件头，校验 ELF 魔数是否合法。
/// 3. 为进程分配新的页表（PageTable），尚未替换进程当前页表。
/// 4. 依次读取 ELF 程序头表的每个段信息，
///    - 验证程序段的合法性（大小、地址对齐等）
///    - 为程序段分配用户虚拟内存空间
///    - 加载程序段数据到相应虚拟地址
/// 5. 在程序段末尾分配两页用户栈空间（一页作为栈，另一页作为栈保护页）。
/// 6. 将传入的命令行参数逐个拷贝进用户栈，构造用户栈上的 argv 数组。
/// 7. 更新进程数据结构中的页表、地址空间大小、程序入口点（epc）和栈指针（sp）。
/// 8. 释放旧的页表对应资源，返回命令行参数数量。
///
/// 参数
/// - `p: &mut Proc`
///   目标进程的可变引用，用于加载可执行文件及更新进程状态。
/// - `path: &[u8]`
///   ELF 文件路径的字节切片表示，需满足文件系统格式。
/// - `argv: &[Option<Box<[u8; MAXARGLEN]>>]`
///   命令行参数数组，元素为可选的固定大小字节数组，参数内容必须以空字节结尾。
///
/// 返回值
/// - `Result<usize, &'static str>`
///   成功时返回命令行参数数量 `argc`；
///   失败时返回静态字符串错误信息，说明失败原因。
///
/// 可能的错误
/// - 无法定位到指定路径对应的 inode（"cannot name inode"）
/// - 读取 ELF 文件头失败（"cannot read elf inode"）
/// - ELF 魔数校验失败（"bad elf magic number"）
/// - 内存不足，无法分配新页表（"mem not enough"）
/// - 读取程序头失败（"cannot read elf program header"）
/// - 程序头元数据不合法（"one program header meta not correct"）
/// - 用户虚拟内存不足，无法为程序段分配空间（"not enough uvm for program header"）
/// - 程序段加载失败（"load program section error"）
/// - 用户虚拟内存不足，无法分配用户栈（"not enough uvm for user stack"）
/// - 命令行参数拷贝失败或超出栈空间限制（"cmd args too much for stack" / "copy cmd args to pagetable go wrong"）
///
/// 安全性
/// - 该函数通过严格校验 ELF 头与程序段元数据保证加载的合法性，避免内存越界和地址不对齐的问题。
/// - 加载过程使用 Rust 的所有权机制和显式资源释放（drop）确保 inode、页表等资源及时释放，防止内存泄漏。
/// - 参数字符串长度和堆栈空间均有严格限制，防止栈溢出。
/// - 该函数中存在大量 `unsafe` 操作（如 `assume_init` 和裸指针转换），
///   调用时必须保证输入路径和 ELF 文件的完整正确性，否则可能引发未定义行为。
/// - 新页表替换旧页表时保证旧资源释放，避免内存泄漏或悬挂指针。
/// - 不允许中断或异步信号干扰该过程，确保加载一致性。
pub fn load(p: &mut Proc, path: &[u8], argv: &[Option<Box<[u8; MAXARGLEN]>>]) -> Result<usize, &'static str> {
    // get relevant inode using path
    let inode: Inode;
    LOG.begin_op();
    match ICACHE.namei(path) {
        Some(i) => inode = i,
        None => {
            LOG.end_op();
            return Err("cannot name inode")
        },
    }

    // check elf header
    // create a new empty pagetable, but not assign yet
    let mut idata = inode.lock();
    let mut elf = MaybeUninit::<ElfHeader>::uninit();
    if idata.iread(
        Address::KernelMut(elf.as_mut_ptr() as *mut u8),
        0, 
        mem::size_of::<ElfHeader>() as u32
    ).is_err() {
        drop(idata); drop(inode); LOG.end_op();
        return Err("cannot read elf inode")
    }
    let elf = unsafe { elf.assume_init() };
    if elf.magic != ELF_MAGIC {
        drop(idata); drop(inode); LOG.end_op();
        return Err("bad elf magic number")
    }

    // allocate new pagetable, not assign to proc yet
    let pdata = p.data.get_mut();
    let mut pgt;
    match PageTable::alloc_proc_pagetable(pdata.tf as usize) {
        Some(p) => pgt = p,
        None => {
            drop(idata); drop(inode); LOG.end_op();
            return Err("mem not enough")
        },
    }
    let mut proc_size = 0usize;

    // load each program section
    let ph_size = mem::size_of::<ProgHeader>() as u32;
    let mut off = elf.phoff as u32;
    for _ in 0..elf.phnum {
        let mut ph = MaybeUninit::<ProgHeader>::uninit();
        if idata.iread(Address::KernelMut(ph.as_mut_ptr() as *mut u8), off, ph_size).is_err() {
            pgt.dealloc_proc_pagetable(proc_size);
            drop(pgt); drop(idata); drop(inode); LOG.end_op();
            return Err("cannot read elf program header")
        }
        let ph = unsafe { ph.assume_init() };
        
        if ph.pg_type != ELF_PROG_LOAD {
            off += ph_size;
            continue;
        }

        if ph.memsz < ph.filesz || ph.vaddr + ph.memsz < ph.vaddr || ph.vaddr % (PGSIZE as u64) != 0 {
            pgt.dealloc_proc_pagetable(proc_size);
            drop(pgt); drop(idata); drop(inode); LOG.end_op();
            return Err("one program header meta not correct")
        }

        match pgt.uvm_alloc(proc_size, (ph.vaddr + ph.memsz) as usize) {
            Ok(cur_size) => proc_size = cur_size,
            Err(_) => {
                pgt.dealloc_proc_pagetable(proc_size);
                drop(pgt); drop(idata); drop(inode); LOG.end_op();
                return Err("not enough uvm for program header")
            }
        }

        if load_seg(pgt.as_mut(), ph.vaddr as usize, &mut idata, ph.off as u32, ph.filesz as u32).is_err() {
            pgt.dealloc_proc_pagetable(proc_size);
            drop(pgt); drop(idata); drop(inode); LOG.end_op();
            return Err("load program section error")
        }

        off += ph_size;
    }
    drop(idata);
    drop(inode);
    LOG.end_op();

    // allocate two page for user stack
    // one for usage, the other for guarding
    proc_size = pg_round_up(proc_size);
    match pgt.uvm_alloc(proc_size, proc_size + 2*PGSIZE) {
        Ok(ret_size) => proc_size = ret_size,
        Err(_) => {
            pgt.dealloc_proc_pagetable(proc_size);
            return Err("not enough uvm for user stack")
        },
    }
    pgt.uvm_clear(proc_size - 2*PGSIZE);
    let mut stack_pointer = proc_size;
    let stack_base = stack_pointer - PGSIZE;

    // prepare command line content in the user stack
    let argc = argv.len();
    debug_assert!(argc < MAXARG);
    let mut ustack = [0usize; MAXARG+1];
    for i in 0..argc {
        let arg_slice = argv[i].as_deref().unwrap();
        let max_pos = arg_slice.iter().position(|x| *x==0).unwrap();
        let count = max_pos + 1;    // counting the ending zero
        stack_pointer -= count;
        stack_pointer = align_sp(stack_pointer);
        if stack_pointer < stack_base {
            pgt.dealloc_proc_pagetable(proc_size);
            return Err("cmd args too much for stack")
        }
        if pgt.copy_out(arg_slice.as_ptr(), stack_pointer, count).is_err() {
            pgt.dealloc_proc_pagetable(proc_size);
            return Err("copy cmd args to pagetable go wrong")
        }
        ustack[i] = stack_pointer;
    }
    debug_assert!(argc == 0 || ustack[argc-1] != 0);    // ustack[argc-1] should not be zero
    debug_assert_eq!(ustack[argc], 0);                  // ustack[argc] should be zero
    stack_pointer -= (argc+1) * mem::size_of::<usize>();
    stack_pointer = align_sp(stack_pointer);
    if stack_pointer < stack_base {
        pgt.dealloc_proc_pagetable(proc_size);
        return Err("cmd args too much for stack")
    }
    if pgt.copy_out(ustack.as_ptr() as *const u8, stack_pointer, (argc+1)*mem::size_of::<usize>()).is_err() {
        pgt.dealloc_proc_pagetable(proc_size);
        return Err("copy cmd args to pagetable go wrong")
    }

    // update the process's info
    let tf = unsafe { pdata.tf.as_mut().unwrap() };
    tf.a1 = stack_pointer;
    let off = path.iter().position(|x| *x!=b'/').unwrap();
    let count = min(path.len()-off, pdata.name.len());
    for i in 0..count {
        pdata.name[i] = path[i+off];
    }
    let mut old_pgt = pdata.pagetable.replace(pgt).unwrap();
    let old_size = pdata.sz;
    pdata.sz = proc_size;
    tf.epc = elf.entry as usize;
    tf.sp = stack_pointer;
    old_pgt.dealloc_proc_pagetable(old_size);
    
    Ok(argc)
}

/// 功能说明
/// 将 ELF 程序段的数据加载到指定进程的用户虚拟内存中。
/// 函数会根据给定的虚拟地址 `va` 和文件偏移 `offset`，
/// 将文件中 `size` 字节的数据读入用户空间对应的物理页面。
/// 该函数假设虚拟地址已经按页大小对齐，且对应的虚拟内存页已经被映射。
///
/// 流程解释
/// 1. 检查传入的虚拟地址 `va` 是否页对齐，若不对齐则直接 panic。
/// 2. 将 `va` 转换为 `VirtAddr` 类型便于地址操作。
/// 3. 以页为单位循环遍历整个段大小 `size`：
///    - 使用页表 `pgt` 查询当前虚拟页对应的物理地址，若未映射则 panic。
///    - 计算本页需要读取的数据字节数（最后一页可能不足一页）。
///    - 从 inode 数据 `idata` 读取对应偏移位置的数据到物理地址。
///    - 虚拟地址前进一页，继续加载下一页。
/// 4. 所有数据加载成功则返回 Ok(())。
///
/// 参数
/// - `pgt: &mut PageTable`
///   目标进程的页表引用，用于虚拟地址到物理地址的转换。
/// - `va: usize`
///   程序段加载的起始虚拟地址，要求页对齐。
/// - `idata: &mut SleepLockGuard<'_, InodeData>`
///   文件 inode 数据的锁保护引用，用于读取文件内容。
/// - `offset: u32`
///   程序段在文件中的偏移量。
/// - `size: u32`
///   程序段的文件大小，表示需要加载的数据字节数。
///
/// 返回值
/// - `Result<(), ()>`
///   成功时返回 `Ok(())`，
///   读取文件数据失败时返回 `Err(())`。
///
/// 可能的错误
/// - 虚拟地址 `va` 未按页大小对齐时触发 panic。
/// - 虚拟地址对应的页未映射时触发 panic。
/// - 从 inode 读取数据失败时返回 `Err(())`。
///
/// 安全性
/// - 该函数依赖调用者保证虚拟地址已正确映射，
///   否则会通过 panic 明确提示，避免后续不可控行为。
/// - 读取文件时持有 inode 数据锁，防止并发访问导致数据竞态。
/// - 读写操作均使用内核态地址转换，保证内存访问合法。
/// - 不包含任何 unsafe 代码，符合 Rust 安全编码规范。
fn load_seg(pgt: &mut PageTable, va: usize, idata: &mut SleepLockGuard<'_, InodeData>, offset: u32, size: u32)
    -> Result<(), ()>
{
    if va % PGSIZE != 0 {
        panic!("va={} is not page aligned", va);
    }
    let mut va = VirtAddr::try_from(va).unwrap();

    for i in (0..size).step_by(PGSIZE) {
        let pa: usize;
        match pgt.walk_addr_mut(va) {
            Ok(phys_addr) => pa = phys_addr.into_raw(),
            Err(s) => panic!("va={} should already be mapped, {}", va.into_raw(), s),
        }
        let count = if size - i < (PGSIZE as u32) {
            size - i
        } else {
            PGSIZE as u32
        };
        if idata.iread(Address::KernelMut(pa as *mut u8), offset+i, count).is_err() {
            return Err(())
        }
        va.add_page();
    }

    Ok(())
}

#[inline(always)]
fn align_sp(sp: usize) -> usize {
    sp - (sp % 16)
}

/// ELF 文件头结构体，表示 ELF 可执行文件的起始元信息。
/// 用于解析 ELF 文件格式，获取程序入口、段表偏移、节表偏移等关键数据，
/// 是加载 ELF 文件到进程地址空间的基础数据结构。
#[repr(C)]
struct ElfHeader {
    /// ELF 魔数，用于标识该文件是否为有效 ELF 文件，固定值 0x464C457F。
    magic: u32,
    /// ELF 标识字节，包含文件类型、字节序、版本等信息。
    elf: [u8; 12],
    /// 文件类型，指示该 ELF 文件是可重定位文件、可执行文件或共享对象等。
    elf_type: u16,
    /// 目标机器架构编号，例如 x86、RISC-V 等。
    machine: u16,
    /// ELF 文件版本，通常为 1。
    version: u32,
    /// 程序入口点虚拟地址，CPU 启动后执行的第一条指令地址。
    entry: u64,
    /// 程序头表在文件中的偏移量，用于定位程序段信息。
    phoff: u64,
    /// 节头表在文件中的偏移量，用于定位节区段信息（动态链接时用）。
    shoff: u64,
    /// 处理器相关标志位，通常为 0。
    flags: u32,
    /// ELF 头部自身的大小（字节数）。
    ehsize: u16,
    /// 程序头表中单个条目的大小。
    phentsize: u16,
    /// 程序头表中条目数量，即程序段数量。
    phnum: u16,
    /// 节头表中单个条目的大小。
    shentsize: u16,
    /// 节头表中条目数量。
    shnum: u16,
    /// 节头字符串表索引，指向节头表中的字符串节。
    shstrndx: u16,
}


/// ELF 程序头结构体，描述 ELF 文件中的单个程序段信息。
/// 用于在加载 ELF 可执行文件时，指示操作系统如何映射该段到进程的虚拟内存空间。
/// 包含程序段的类型、访问权限、文件偏移、内存地址、大小和对齐要求等关键信息。
#[repr(C)]
struct ProgHeader {
    /// 程序段类型，指示该段的用途，如加载段（LOAD）、动态链接信息等。
    pg_type: u32,
    /// 段的访问权限标志，如可读、可写、可执行。
    flags: u32,
    /// 程序段在文件中的偏移量。
    off: u64,
    /// 程序段映射到进程虚拟内存的起始地址。
    vaddr: u64,
    /// 物理地址（通常未使用，现代系统多忽略）。
    paddr: u64,
    /// 程序段在文件中的大小（字节数）。
    filesz: u64,
    /// 程序段在内存中的大小（字节数），通常 >= filesz。
    memsz: u64,
    /// 程序段对齐要求，通常为页大小的整数倍。
    align: u64,
}


const ELF_MAGIC: u32 = 0x464C457F;
const ELF_PROG_LOAD: u32 = 1;
