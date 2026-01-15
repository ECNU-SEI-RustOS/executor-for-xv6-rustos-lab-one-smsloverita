use alloc::sync::Arc;
use core::mem;
use core::num::Wrapping;
use core::sync::atomic::{Ordering, AtomicUsize};
use core::cmp::min;
use core::ptr::addr_of_mut;

use crate::consts::fs::{PIPESIZE, PIPESIZE_U32};
use crate::process::{CPU_MANAGER, PROC_MANAGER};
use crate::spinlock::SpinLock;

use super::{File, FileInner};

/// 表示一个内核态的管道（pipe）通信结构，封装了对 `PipeInner` 的同步访问。
///
/// `Pipe` 提供了对进程间通信（IPC）的支持，允许一个进程写入数据，
/// 并被另一个进程读取。内部通过 [`SpinLock`] 实现对 [`PipeInner`] 的互斥访问，
/// 以保障多核环境下并发读写的正确性与一致性。
///
/// 管道采用固定大小的环形缓冲区进行数据传输，并结合进程的休眠与唤醒机制，
/// 实现对读写双方的阻塞控制和同步通信能力。
///
/// 本结构体通常由 [`FileInner::Pipe`] 所引用，通过 [`File`] 文件抽象与用户进程交互。
#[derive(Debug)]
pub struct Pipe(SpinLock<PipeInner>);


impl Pipe {
    /// 创建一个 [`Pipe`] 实例，并生成一对对应的读写文件接口。
    ///
    /// # 功能说明
    /// 该函数初始化一个管道对象，并创建两个 [`File`] 实例，分别用于读端和写端，
    /// 从而支持用户进程之间的双向通信。该函数对应于 Unix 风格的 pipe() 系统调用实现，
    /// 并将内核态的管道结构抽象为用户可读写的文件接口。
    ///
    /// # 流程解释
    /// 1. 使用 `Arc::try_new_zeroed` 申请未初始化的 [`Pipe`] 空间；
    /// 2. 使用 `SpinLock::init_name` 初始化管道内的自旋锁（用于调试）；
    /// 3. 初始化 `PipeInner` 中的读写状态；
    /// 4. 构造两个 [`File`] 对象，一个可读、一个可写，并都引用该管道；
    /// 5. 若任意资源分配失败，返回 `None`。
    ///
    /// # 参数
    /// 无输入参数。
    ///
    /// # 返回值
    /// - 成功时返回 `Some((read_file, write_file))`，其中：
    ///   - `read_file`: 只读文件，绑定到管道的读端；
    ///   - `write_file`: 只写文件，绑定到管道的写端；
    /// - 如果分配内存或构造文件对象失败，返回 `None`。
    ///
    /// # 可能的错误
    /// - 内存不足或 `Arc::try_new_zeroed` / `Arc::try_new` 分配失败；
    /// - 内部未能正确初始化管道锁或构造文件结构体。
    ///
    /// # 安全性
    /// - 使用 `unsafe` 语句块对未初始化的 `Pipe` 执行原地初始化，
    ///   要求调用者确保 `Arc::get_mut_unchecked` 的唯一性前提成立；
    /// - 使用 `assume_init` 对 `MaybeUninit<Arc<Pipe>>` 解包，必须确保已完成所有字段初始化；
    /// - 此操作在受控环境下是安全的，因本函数是 `create` 的唯一初始化入口。
    pub fn create() -> Option<(Arc<File>, Arc<File>)> {
        debug_assert!(mem::size_of::<Pipe>() <= 512-2*mem::size_of::<AtomicUsize>());

        // create a pipe
        let mut pipe = Arc::<Self>::try_new_zeroed().ok()?;
        let pipe = unsafe {
            let ptr = Arc::get_mut_unchecked(&mut pipe).as_mut_ptr();
            SpinLock::init_name(addr_of_mut!((*ptr).0), "pipe");
            pipe.assume_init()
        };
        let mut guard = pipe.0.lock();
        guard.read_open = true;
        guard.write_open = true;
        drop(guard);

        // create two files
        let read_file = Arc::try_new(File {
            inner: FileInner::Pipe(Arc::clone(&pipe)),
            readable: true,
            writable: false,
        }).ok()?;
        let write_file = Arc::try_new(File {
            inner: FileInner::Pipe(Arc::clone(&pipe)),
            readable: false,
            writable: true,
        }).ok()?;

        Some((read_file, write_file))
    }

    /// 从管道中读取数据，将字节复制到用户空间缓冲区中。
    ///
    /// # 功能说明
    /// 尝试从当前管道读取最多 `count` 个字节，将读取的数据复制到用户进程的地址空间中。
    /// 若当前管道为空且写端仍开启，则进程进入休眠等待写端写入数据。
    /// 支持环形缓冲区读取、读写阻塞同步，并在数据可读或写端关闭后恢复执行。
    ///
    /// # 流程解释
    /// - 获取当前进程指针 `p`；
    /// - 通过 `SpinLock` 加锁管道内部状态；
    /// - 若管道为空且写端未关闭，则调用 `p.sleep()` 阻塞当前进程，直到有数据可读或写端关闭；
    /// - 重新加锁后计算可读字节数（读写指针差值），逐字节复制到用户空间；
    /// - 若中途发生复制错误，则提前结束读取；
    /// - 更新读指针 `read_cnt`，并唤醒可能因缓冲区满而阻塞的写进程。
    ///
    /// # 参数
    /// - `addr`: 用户空间中的目标地址，数据将复制到该地址开始的缓冲区；
    /// - `count`: 请求读取的最大字节数。
    ///
    /// # 返回值
    /// - `Ok(n)`：实际成功读取并复制的字节数 `n`；
    /// - `Err(())`：如果当前进程被标记为已终止（`killed == true`），则返回错误。
    ///
    /// # 可能的错误
    /// - 进程在等待数据期间被外部标记为终止，读取中断，返回 `Err(())`；
    /// - 复制数据至用户空间失败时，提前终止读取过程，返回部分数据（非错误）。
    ///
    /// # 安全性
    /// - 使用 `unsafe` 获取当前进程指针 `p`，需确保调用者在内核上下文中且该指针有效；
    /// - 用户空间地址 `addr` 的有效性由 `copy_out()` 检查与处理；
    /// - 锁的获取、释放、睡眠与唤醒操作在受控环境中调用，确保不会造成死锁或竞态。
    pub(super) fn read(&self, addr: usize, count: u32) -> Result<u32, ()> {
        let p = unsafe { CPU_MANAGER.my_proc() };

        let mut pipe = self.0.lock();

        // wait for data to be written
        while pipe.read_cnt == pipe.write_cnt && pipe.write_open {
            if p.killed.load(Ordering::Relaxed) {
                return Err(())
            }
            p.sleep(&pipe.read_cnt as *const Wrapping<_> as usize, pipe);
            pipe = self.0.lock();
        }

        // read from pipe to user memory
        let count = min(count, (pipe.write_cnt - pipe.read_cnt).0);
        let mut read_count = count;
        for i in 0..count {
            let index = (pipe.read_cnt.0 % PIPESIZE_U32) as usize;
            let byte = pipe.data[index];
            pipe.read_cnt += Wrapping(1);
            if p.data.get_mut().copy_out(&byte as *const u8, addr+(i as usize), 1).is_err() {
                read_count = i;
                break
            }
        }
        unsafe { PROC_MANAGER.wakeup(&pipe.write_cnt as *const Wrapping<_> as usize); }
        drop(pipe);
        Ok(read_count)
    }

    /// 向管道写入数据，从用户空间缓冲区读取字节写入环形缓冲区。
    ///
    /// # 功能说明
    /// 尝试从用户空间地址 `addr` 读取最多 `count` 个字节，并写入当前管道的缓冲区中。
    /// 如果管道写满，则当前进程会被阻塞直到缓冲区中有可用空间或读端被关闭。
    /// 支持读写端同步机制和用户态数据拷贝，并自动处理写阻塞与唤醒逻辑。
    ///
    /// # 流程解释
    /// - 获取当前进程指针 `p`；
    /// - 加锁管道以访问内部状态；
    /// - 持续尝试写入数据：
    ///   - 若写端尚未完成，且缓冲区未满，则从用户空间复制一个字节至缓冲区；
    ///   - 若缓冲区已满，则唤醒读进程，并将当前进程阻塞在写端等待点；
    ///   - 若读端已关闭或当前进程被终止，则立即中断写入并返回错误。
    /// - 每次写入后推进写指针 `write_cnt`，最终返回成功写入的字节数。
    /// - 写入完成后唤醒读进程以通知数据可读。
    ///
    /// # 参数
    /// - `addr`：用户空间中源缓冲区的起始地址；
    /// - `count`：尝试写入的最大字节数。
    ///
    /// # 返回值
    /// - `Ok(n)`：成功写入的字节数 `n`；
    /// - `Err(())`：当读端已关闭或进程已被标记为终止时，返回错误。
    ///
    /// # 可能的错误
    /// - 若读端被关闭，`read_open == false`，则立即返回 `Err(())`；
    /// - 若当前进程在阻塞期间被标记为 `killed`，则中止写入并返回错误；
    /// - 若 `copy_in()` 从用户地址复制失败，则提前终止写入，返回已写入的字节数。
    ///
    /// # 安全性
    /// - 使用 `unsafe` 获取当前进程指针 `p`，调用上下文需保证在有效的内核态；
    /// - 用户空间地址的读取通过 `copy_in()` 进行边界检查与错误控制；
    /// - 锁操作、进程休眠与唤醒在管道内部状态一致性前提下安全使用；
    /// - 写入操作严格限制在环形缓冲区有效索引范围内，避免越界访问。
    pub(super) fn write(&self, addr: usize, count: u32) -> Result<u32, ()> {
        let p = unsafe { CPU_MANAGER.my_proc() };

        let mut pipe = self.0.lock();

        let mut write_count = 0;
        while write_count < count {
            if !pipe.read_open || p.killed.load(Ordering::Relaxed) {
                return Err(())
            }

            if pipe.write_cnt == pipe.read_cnt + Wrapping(PIPESIZE_U32) {
                // wait for data to be read
                unsafe { PROC_MANAGER.wakeup(&pipe.read_cnt as *const Wrapping<_> as usize); }
                p.sleep(&pipe.write_cnt as *const Wrapping<_> as usize, pipe);
                pipe = self.0.lock();
            } else {
                let mut byte: u8 = 0;
                if p.data.get_mut().copy_in(addr+(write_count as usize), &mut byte, 1).is_err() {
                    break;                    
                }
                let i = (pipe.write_cnt.0 % PIPESIZE_U32) as usize;
                pipe.data[i] = byte;
                pipe.write_cnt += Wrapping(1);
                write_count += 1;
            }
        }
        unsafe { PROC_MANAGER.wakeup(&pipe.read_cnt as *const Wrapping<_> as usize); }
        drop(pipe);
        Ok(write_count)
    }

    /// 关闭管道的一端，通知另一端的可能阻塞进程解除休眠。
    ///
    /// # 功能说明
    /// 根据参数决定关闭管道的读端或写端。该操作会修改管道内部状态，
    /// 并唤醒另一端因等待数据或缓冲区而可能阻塞的进程，从而促使其继续执行或检测到关闭事件。
    /// 这是管道资源回收流程的一部分，通常在文件关闭时调用。
    ///
    /// # 流程解释
    /// - 加锁访问 `PipeInner`；
    /// - 若关闭的是写端：
    ///   - 设置 `write_open = false`；
    ///   - 唤醒所有阻塞在 `read_cnt` 上的读进程，以便它们在下一次尝试读取时感知写端关闭；
    /// - 若关闭的是读端：
    ///   - 设置 `read_open = false`；
    ///   - 唤醒所有阻塞在 `write_cnt` 上的写进程，以便它们在下一次尝试写入时感知读端关闭。
    ///
    /// # 参数
    /// - `is_write`：布尔值，指示关闭的是否是写端；
    ///   - 若为 `true`，关闭写端；
    ///   - 若为 `false`，关闭读端。
    ///
    /// # 返回值
    /// 无返回值。
    ///
    /// # 可能的错误
    /// - 本函数本身不会返回错误，但调用者应确保不重复关闭已关闭的端，
    ///   否则可能导致逻辑上的双重关闭。
    ///
    /// # 安全性
    /// - 唤醒操作通过 `PROC_MANAGER.wakeup` 实现，需保证唤醒地址来源合法（即 `read_cnt`/`write_cnt` 字段的地址）；
    /// - 通过 `SpinLock` 保证对管道状态的互斥访问，防止并发修改带来不一致。
    pub(super) fn close(&self, is_write: bool) {
        let mut pipe = self.0.lock();
        if is_write {
            pipe.write_open = false;
            unsafe { PROC_MANAGER.wakeup(&pipe.read_cnt as *const Wrapping<_> as usize); }
        } else {
            pipe.read_open = false;
            unsafe { PROC_MANAGER.wakeup(&pipe.write_cnt as *const Wrapping<_> as usize); }
        }
    }
}

impl Drop for Pipe {
    /// 在 [`Pipe`] 被销毁时触发的清理检查逻辑，确保资源生命周期一致性。
    ///
    /// # 功能说明
    /// 该函数实现 [`Drop`] 特性，用于在 `Pipe` 实例被最后一个 `Arc` 所释放时执行调试断言，
    /// 检查管道的读端与写端是否已同时关闭。该检查用于验证管道的生命周期管理是否正确，
    /// 防止出现资源悬挂或提前销毁的逻辑错误。
    ///
    /// # 流程解释
    /// - 使用 `SpinLock` 获取对内部管道状态的只读访问；
    /// - 断言 `read_open` 和 `write_open` 状态相等；
    /// - 若该断言失败，则在调试构建中触发 panic，提示生命周期管理错误。
    ///
    /// # 参数
    /// - `&mut self`：被销毁的管道实例的可变引用。
    ///
    /// # 返回值
    /// 无返回值。
    ///
    /// # 可能的错误
    /// - 若在 `debug` 模式下管道被销毁时只关闭了一端（`read_open != write_open`），
    ///   则触发 panic，表示管道未被正常关闭。
    /// - `release` 时未确保正确关闭所有文件描述符，可能引发此断言失败。
    ///
    /// # 安全性
    /// - 本函数不涉及 `unsafe` 操作；
    fn drop(&mut self) {
        debug_assert!({
            let guard = self.0.lock();
            guard.read_open == guard.write_open
        });
    }
}

/// 表示内核管道的内部状态，用于管理数据缓冲区与读写端口状态。
///
/// `PipeInner` 是 `Pipe` 的核心数据结构，负责维护管道的状态与数据传输逻辑，
/// 包括读写端是否开启、当前的读写偏移量，以及一个定长的环形缓冲区。
/// 该结构由外层的 [`SpinLock`] 保护，确保在并发读写或关闭时的数据一致性。
///
/// 管道通过 `read_cnt` 和 `write_cnt` 实现环形缓冲区读写索引的推进，
/// 并结合进程阻塞与唤醒机制，实现进程间的同步通信。
#[derive(Debug)]
struct PipeInner {
    /// 管道的读端是否处于开启状态。
    /// 若为 `false`，说明读端已关闭，写入将失败。
    read_open: bool,

    /// 管道的写端是否处于开启状态。
    /// 若为 `false`，说明写端已关闭，读取将返回 EOF。
    write_open: bool,

    /// 当前读取计数器，表示下一个可读字节的位置（逻辑偏移）。
    /// 使用 [`Wrapping<u32>`] 实现无符号溢出语义，构成环形缓冲区读指针。
    read_cnt: Wrapping<u32>,

    /// 当前写入计数器，表示下一个可写字节的位置（逻辑偏移）。
    /// 同样使用 [`Wrapping<u32>`]，确保写指针在缓冲区内环绕。
    write_cnt: Wrapping<u32>,

    /// 固定大小的字节缓冲区，用于存储写入的数据。
    /// 该缓冲区采用环形策略访问，大小为 `PIPESIZE`。
    data: [u8; PIPESIZE],
}
