//! Log-relevant operations

use core::{ops::{Deref, DerefMut}, panic, ptr};
use core::mem;

use crate::consts::fs::{MAXOPBLOCKS, LOGSIZE, BSIZE};
use crate::process::{CPU_MANAGER, PROC_MANAGER};
use crate::spinlock::SpinLock;
use super::{BCACHE, Buf, SUPER_BLOCK, BufData};

/// 全局唯一的日志子系统实例，用于实现文件系统操作的事务性。
///
/// 该 `LOG` 实例封装在一个 [`SpinLock`] 中，确保在多核环境中对日志元数据（如日志头、提交状态、正在进行的操作计数）访问的同步安全。
/// 日志系统用于追踪并缓冲磁盘上的修改操作，在崩溃恢复过程中可通过日志回滚或重做未完成的事务，提供类似写时复制（Write-Ahead Logging）的机制，
/// 以保证文件系统的一致性与原子性。
///
/// 日志的生命周期与文件系统一致，在内核启动阶段调用 [`Log::init`] 初始化，
/// 在每次文件系统调用开始和结束处通过 [`begin_op`] 与 [`end_op`] 管理事务边界。
///
/// # 实现说明
/// - 仅存在一个 `LOG` 实例，作为文件系统写操作的统一入口。
/// - 内部使用 `Log` 类型表示日志核心数据结构，包含日志头、日志区块范围、设备号等字段。
/// - 在事务提交阶段（由 `end_op` 最后一个操作触发），将缓存在日志区块中的数据拷贝到原位置，并清空日志头。
pub static LOG: SpinLock<Log> = SpinLock::new(Log::uninit(), "log");

/// 用于记录和管理文件系统日志的核心结构体。
///
/// `Log` 结构体实现了一个简化的事务性日志机制，模仿 xv6 中的 write-ahead log，
/// 以确保多步文件系统更新的原子性与崩溃恢复能力。
/// 它记录了日志区域的位置、事务状态以及当前事务中涉及的块号，
/// 并通过配套的操作函数（如 `commit`, `recover`, `write_head` 等）
/// 提供日志写入与回滚功能。
///
/// 该结构体由全局唯一的 [`LOG`] 实例持有，并封装在 [`SpinLock`] 中，
/// 确保在并发环境中操作的同步安全。
pub struct Log {
    /// 日志区在磁盘中的起始块号（由超级块中读取）
    start: u32,
    /// 日志区域中可用块的数量（包括日志头块和数据块）
    size: u32,
    /// 所在磁盘设备的编号
    dev: u32,
    /// 当前正在进行的文件系统操作数（事务嵌套层数）
    outstanding: u32,
    /// 指示日志系统是否正在提交事务，
    /// 为 true 时禁止新的文件系统操作进入
    committing: bool,
    /// 当前事务的日志头，记录了修改的块号及数量
    lh: LogHeader,
}

impl Log {
    const fn uninit() -> Self {
        Self {
            start: 0,
            size: 0,
            dev: 0,
            outstanding: 0,
            committing: false,
            lh: LogHeader { len: 0, blocknos: [0; LOGSIZE-1] },
        }
    }

    /// 初始化日志系统并在必要时执行崩溃恢复。
    ///
    /// # 功能说明
    /// 本函数在文件系统启动阶段调用，负责从超级块读取日志区域的起始位置与大小，
    /// 并初始化日志系统的内部状态。若检测到存在未完成的事务（即日志头中仍有记录），
    /// 则会自动触发恢复逻辑，将日志区中的修改写回其原始块位置，以保证文件系统一致性。
    ///
    /// # 流程解释
    /// 1. 断言日志头结构体大小小于块大小，且对齐要求能被 BufData 满足；
    /// 2. 调用 `SUPER_BLOCK.read_log()` 读取日志区域的 `start` 和 `size`；
    /// 3. 保存日志设备号 `dev`；
    /// 4. 调用 `self.recover()` 执行恢复操作（如需要）。
    ///
    /// # 参数
    /// - `dev`: 日志所在的块设备编号，由调用者传入，通常在系统引导阶段由磁盘管理子系统指定。
    ///
    /// # 返回值
    /// 无返回值。该函数通过更新 `Log` 结构体内部字段来完成初始化。
    ///
    /// # 可能的错误
    /// - 如果 `LogHeader` 的大小超过块大小 `BSIZE`，将触发调试断言失败；
    /// - 若其对齐要求无法被缓冲区 `BufData` 满足，也会触发断言；
    /// - 若调用时持有自旋锁，会导致后续的磁盘 I/O 操作在睡眠时引发死锁或不安全行为。
    ///
    /// # 安全性
    /// 这是一个 `unsafe` 函数，因为它依赖磁盘读写操作，可能导致阻塞（`sleep`）行为。
    /// 要求调用者在未持有任何锁的情况下调用本函数，确保不会违反内核中的锁顺序原则。
    pub unsafe fn init(&mut self, dev: u32) {
        debug_assert!(mem::size_of::<LogHeader>() < BSIZE);
        debug_assert_eq!(mem::align_of::<BufData>() % mem::align_of::<LogHeader>(), 0);
        let (start, size) = SUPER_BLOCK.read_log();
        self.start = start;
        self.size = size;
        self.dev = dev;
        self.recover();
    }

    /// 执行文件系统的日志恢复流程（若存在未完成事务）。
    ///
    /// # 功能说明
    /// 该函数用于在系统启动阶段检查日志头中的事务记录是否未被提交，
    /// 若检测到存在未完成的日志条目，则说明上次文件系统操作未完全落盘，可能由于系统崩溃或掉电。
    /// 此时通过将日志区中的数据拷贝回其原始位置来完成恢复，以确保文件系统的一致性。
    ///
    /// # 流程解释
    /// 1. 调用 [`read_head`] 将磁盘上的日志头加载到内存中的 `self.lh`；
    /// 2. 若日志头中的 `len` 字段大于 0，说明存在需要恢复的日志内容；
    ///     - 调用 [`install_trans`] 并传入 `recovering = true`，将日志块写回其原始位置；
    ///     - 调用 [`empty_head`] 清空磁盘中的日志头；
    /// 3. 否则无需恢复，函数直接返回。
    ///
    /// # 参数
    /// 无参数。操作对象为当前 `Log` 实例本身。
    ///
    /// # 返回值
    /// 无返回值。该函数会通过副作用修改磁盘内容以及日志头状态。
    ///
    /// # 可能的错误
    /// 本函数本身不包含显式的错误处理逻辑，但调用的 `bread` 或 `bwrite` 等函数可能因磁盘故障或缓存失效导致下层错误。
    /// 此外，如果日志头损坏（如 `len` 非法）将可能引发错误行为（需由上层引导阶段保证一致性）。
    ///
    /// # 安全性
    /// 本函数不涉及 `unsafe` 操作，但其调用的 I/O 过程（如读写缓存块）可能阻塞，因此不应在持锁状态下调用。
    /// 应仅由启动阶段或其他显式序列中触发，确保执行环境安全可控。
    fn recover(&mut self) {
        println!("file system: checking logs");
        self.read_head();
        if self.lh.len > 0 {
            println!("file system: recovering from logs");
            self.install_trans(true);
            self.empty_head();
        } else {
            println!("file system: no need to recover");
        }
    }

   /// 从磁盘中读取日志头，并加载到内存中的日志头结构中。
    fn read_head(&mut self) {
        let buf = BCACHE.bread(self.dev, self.start);
        unsafe {
            ptr::copy_nonoverlapping(
                buf.raw_data() as *const LogHeader,
                &mut self.lh,
                1
            );
        }
        drop(buf);
    }

    /// 将内存中的日志头写入磁盘。
    /// 这是当前事务真正被提交的时间点。
    fn write_head(&mut self) {
        let mut buf = BCACHE.bread(self.dev, self.start);
        unsafe {
            ptr::copy_nonoverlapping(
                &self.lh,
                buf.raw_data_mut() as *mut LogHeader,
                1,
            );
        }
        buf.bwrite();
        drop(buf);
    }

    /// 清空日志头，将日志的长度字段（内存和磁盘中）都设置为零。
    ///
    /// # 功能说明
    /// 此函数用于在事务提交完成后重置日志头，表示日志区域为空，当前没有待提交的事务。
    /// 它会同时更新内存中的日志头结构体 `self.lh` 和磁盘上的日志头块，确保一致性。
    ///
    /// # 流程解释
    /// 1. 将内存中日志头的 `len` 字段设置为 0；
    /// 2. 从磁盘读取日志头所在块（即日志起始块）；
    /// 3. 将该块中的 `LogHeader.len` 字段也设置为 0；
    /// 4. 调用 `bwrite` 将修改后的日志头块写回磁盘。
    ///
    /// # 参数
    /// 无参数。操作对象为当前 `Log` 实例本身。
    ///
    /// # 返回值
    /// 无返回值。该函数通过副作用修改内存与磁盘中的日志头。
    ///
    /// # 可能的错误
    /// - 如果 `bread` 读取块失败或 `bwrite` 写入失败，可能造成日志头未被正确清空；
    /// - 如果 `raw_data_mut` 指针转换失败或非法使用，可能引发未定义行为（由 `unsafe` 保证正确性）。
    ///
    /// # 安全性
    /// 本函数内部使用了 `unsafe` 指针转换与解引用，因此必须确保缓冲区的数据确实包含合法的 `LogHeader` 并具有正确对齐；
    /// 此外，必须保证在非并发访问场景中调用（通常由日志提交过程控制），以防止数据竞争。
    fn empty_head(&mut self) {
        self.lh.len = 0;
        let mut buf = BCACHE.bread(self.dev, self.start);
        let raw_lh = buf.raw_data_mut() as *mut LogHeader;
        unsafe { raw_lh.as_mut().unwrap().len = 0; }
        buf.bwrite();
        drop(buf);
    }

    /// 将日志中已提交的块复制回它们原本在磁盘中的位置。
    ///
    /// # 功能说明
    /// 此函数用于将日志区域中的数据块（代表某次事务的修改内容）拷贝回其“原始位置”，
    /// 是日志系统中完成事务提交或恢复的核心步骤。
    /// 可用于两种场景：
    /// - 正常事务提交（`recovering = false`）：复制数据后解除对缓存块的日志钉住（unpin）；
    /// - 启动时崩溃恢复（`recovering = true`）：仅复制数据，不修改缓存钉住状态。
    ///
    /// # 流程解释
    /// 对于日志头中每一个记录的块号：
    /// 1. 读取对应的日志块（`self.start + 1 + i`）；
    /// 2. 读取该块原本所在的位置（`self.lh.blocknos[i]`）；
    /// 3. 使用 `ptr::copy` 将日志块内容复制到目标块缓冲区；
    /// 4. 调用 `bwrite()` 将目标块写回磁盘；
    /// 5. 若处于非恢复模式，调用 `unpin()` 解除对该块的日志钉住；
    /// 6. 释放两个缓存块。
    ///
    /// # 参数
    /// - `recovering`: 是否处于恢复模式。为 `true` 时表示启动时的日志回放，不解除钉住；
    ///   为 `false` 时表示正常事务提交，提交后解除所有缓存块的钉住状态。
    ///
    /// # 返回值
    /// 无返回值。该函数通过副作用将缓存中的日志数据写回原磁盘位置。
    ///
    /// # 可能的错误
    /// - 如果读取或写入磁盘块（`bread`/`bwrite`）失败，将导致日志内容未能正确持久化；
    /// - 使用 `unsafe` 指针复制操作，若目标缓冲区非法或未对齐，可能造成未定义行为；
    /// - `self.lh.len` 超出合法范围时可能造成越界访问。
    ///
    /// # 安全性
    /// 本函数内部使用 `unsafe` 指针操作对缓存数据进行字节级复制，需保证：
    /// - 两个缓存块内容合法，且具有足够空间；
    /// - 拷贝大小（此处为 1 个块）是安全的；
    /// - 不在多线程并发访问的上下文中调用（应在持有日志锁的情况下进行）；
    /// 此外，`unpin()` 只在非恢复路径中调用，确保恢复路径中不破坏事务隔离。
    fn install_trans(&mut self, recovering: bool) {
        for i in 0..self.lh.len {
            let log_buf  = BCACHE.bread(self.dev, self.start+1+i);
            let mut disk_buf = BCACHE.bread(self.dev, self.lh.blocknos[i as usize]);
            unsafe {
                ptr::copy(
                    log_buf.raw_data(),
                    disk_buf.raw_data_mut(),
                    1,
                );
            }
            disk_buf.bwrite();
            if !recovering {
                unsafe { disk_buf.unpin(); }
            }
            drop(log_buf);
            drop(disk_buf);
        }
    }

    /// 提交日志，将日志中的数据正式写入文件系统。
    ///
    /// # 功能说明
    /// 此函数用于在文件系统操作完成后将本次事务对应的日志内容写入磁盘。
    /// 它代表事务的提交阶段，确保所有缓存在日志区的修改操作被复制到它们原本的磁盘位置。
    /// 提交过程结束后，还会清空日志头，表明日志区已可用于下一次事务。
    ///
    /// # 流程解释
    /// 1. 检查 `committing` 标志是否已设置，若未设置则触发 panic；
    /// 2. 若当前日志长度 `lh.len` 大于 0，执行以下步骤：
    ///     - 调用 [`write_log`]：将缓存中的原始数据块复制到日志块区域；
    ///     - 调用 [`write_head`]：将日志头写入磁盘，标志着事务正式提交；
    ///     - 调用 [`install_trans`]：将日志块中的内容写回到它们的原始位置；
    ///     - 调用 [`empty_head`]：清空日志头，表示日志区可复用。
    ///
    /// # 参数
    /// 无参数。操作对象为当前 `Log` 实例。
    ///
    /// # 返回值
    /// 无返回值。函数通过副作用修改磁盘内容和内部状态。
    ///
    /// # 可能的错误
    /// - 如果调用时未设置 `committing = true`，将触发 panic；
    /// - 若日志头损坏或越界可能导致复制错误；
    /// - 过程中调用的 I/O 函数（如 `bread`, `bwrite`）失败可能影响日志提交完整性；
    /// - 内部 `unsafe` 指针操作若不正确，可能引发未定义行为。
    ///
    /// # 安全性
    /// 本函数为 `unsafe`，调用者必须确保：
    /// - 当前已设置 `committing = true`，表示事务提交阶段；
    /// - 调用过程中未持有锁，以避免潜在的休眠导致死锁；
    /// - 调用路径控制良好，不允许并发或递归提交。
    pub unsafe fn commit(&mut self) {
        if !self.committing {
            panic!("log: committing while the committing flag is not set");
        }
        // debug_assert!(self.lh.len > 0);     // it should have some log to commit
        if self.lh.len > 0 {
            self.write_log();
            self.write_head();
            self.install_trans(false);
            self.empty_head();
        }
    }

    /// 将缓存中的原始数据块复制到日志区域的磁盘块中。
    ///
    /// # 功能说明
    /// 该函数用于在事务提交前将用户修改的缓存数据写入到日志区域（log blocks）中，
    /// 为后续的正式提交（即将数据写回原始位置）做准备。
    /// 它保证即使系统崩溃，也可以在日志区中找到最新的数据用于恢复。
    ///
    /// # 流程解释
    /// 对日志头中记录的每一个块号：
    /// 1. 通过 `lh.blocknos[i]` 找到用户原始数据块的缓存副本；
    /// 2. 找到日志区域中对应的位置 `self.start + 1 + i`（跳过日志头块）；
    /// 3. 将用户数据块的内容复制到日志块中；
    /// 4. 调用 `bwrite` 将日志块持久化写入磁盘；
    /// 5. 释放两个缓存块。
    ///
    /// # 参数
    /// 无参数。操作对象为当前 `Log` 实例。
    ///
    /// # 返回值
    /// 无返回值。函数通过副作用将数据从缓存写入日志磁盘块。
    ///
    /// # 可能的错误
    /// - 如果读取缓存块失败（`bread` 失败）可能导致无法写入日志；
    /// - 使用 `unsafe` 的内存复制指令 `ptr::copy`，若目标数据未对齐或类型不匹配，可能引发未定义行为；
    /// - `lh.len` 越界可能导致访问非法内存。
    ///
    /// # 安全性
    /// 函数内部使用了 `unsafe` 指针操作将缓存块内容进行字节复制，因此需保证：
    /// - 被读取与写入的缓存块内容都是有效的磁盘块；
    /// - 块大小为固定常量（如 `BSIZE`），可确保复制过程安全；
    /// - 在持有日志锁的上下文中调用，防止并发修改。
    fn write_log(&mut self) {
        for i in 0..self.lh.len {
            let mut log_buf  = BCACHE.bread(self.dev, self.start+1+i);
            let cache_buf = BCACHE.bread(self.dev, self.lh.blocknos[i as usize]);
            unsafe {
                ptr::copy(
                    cache_buf.raw_data(),
                    log_buf.raw_data_mut(),
                    1,
                );
            }
            log_buf.bwrite();
            drop(cache_buf);
            drop(log_buf);
        }
    }
}

impl SpinLock<Log> {
    /// 在每次文件系统调用开始时调用，用于标记日志事务的起始。
    ///
    /// # 功能说明
    /// 该函数用于文件系统操作的开头，确保当前事务可以被日志系统接纳。
    /// 它通过增加 `outstanding` 计数来表示一个新的文件系统操作进入，
    /// 并在日志空间不足或日志正在提交时阻塞当前进程，直到可以继续为止。
    ///
    /// # 流程解释
    /// 1. 加锁以获取对日志的独占访问权；
    /// 2. 检查是否满足以下任一条件，若满足则阻塞当前进程：
    ///     - 当前日志正在提交（`committing == true`）；
    ///     - 预计本次操作所需日志块超过剩余空间（估算公式中含 `MAXOPBLOCKS`）；
    /// 3. 若不能立即进入，调用 `sleep` 进入等待状态，直到被 `end_op()` 唤醒；
    /// 4. 若可以进入，递增 `outstanding` 表示开始一个新的日志操作；
    /// 5. 解锁并返回。
    ///
    /// # 参数
    /// 无参数。作用于 `SpinLock<Log>` 的实例，即全局日志管理器。
    ///
    /// # 返回值
    /// 无返回值。通过副作用标记一个新的文件系统事务的开始。
    ///
    /// # 可能的错误
    /// - 若存在日志提交未完成，调用将阻塞当前进程；
    /// - 若估算日志空间不足，也将使当前进程阻塞；
    /// - 若锁的释放和重新获取过程实现不当，可能导致死锁；
    /// - `sleep` 调用依赖当前进程指针存在和可调度，否则可能造成未定义行为。
    ///
    /// # 安全性
    /// 本函数不包含 `unsafe` 块，但依赖对 `SpinLock` 的正确使用和进程调度机制的健壮性。
    /// 为保证安全性：
    /// - 调用者应确保在内核上下文中调用；
    /// - 所有睡眠等待应有相应唤醒机制（由 `end_op` 负责）；
    /// - 本函数不能嵌套调用，也不能在已提交或提交中断的上下文中调用。
    pub fn begin_op(&self) {
        let mut guard  = self.lock();
        loop {
            if guard.committing ||
                1 + guard.lh.len as usize +
                (guard.outstanding+1) as usize * MAXOPBLOCKS > LOGSIZE
            {
                let channel = guard.deref() as *const Log as usize;
                unsafe { CPU_MANAGER.my_proc().sleep(channel, guard); }
                guard = self.lock();
            } else {
                guard.outstanding += 1;
                drop(guard);
                break;
            }
        }
    }

    /// 将给定的缓冲块记录到日志系统中，并在日志提交前固定（pin）该块在缓存中。
    ///
    /// # 功能说明
    /// 本函数用于在一次文件系统写操作中，将被修改的块注册到当前事务的日志头中，
    /// 以便在事务提交时统一写入磁盘。
    /// 被写入日志的缓冲块会被“钉住”（pin），直到事务完成，以防止该块在提交前被驱逐或回收。
    ///
    /// # 流程解释
    /// 1. 加锁以获得日志结构的独占访问权；
    /// 2. 检查日志空间是否足够容纳新记录，若不足则触发 panic；
    /// 3. 检查当前是否处于有效文件系统事务中（`outstanding >= 1`），否则触发 panic；
    /// 4. 遍历日志头，若该块已被记录，则无需重复写入，直接释放资源并返回；
    /// 5. 再次确认空间是否足够（考虑 blocknos 数组 + 日志头），若不足则 panic；
    /// 6. 将该缓冲块钉住，防止在提交前被替换；
    /// 7. 将块号写入日志头，并更新 `len` 字段；
    /// 8. 解锁并释放缓冲块。
    ///
    /// # 参数
    /// - `buf`: 一个需要被记录到日志中的缓冲块（`Buf<'_>`），表示某个将被修改的磁盘块。
    ///
    /// # 返回值
    /// 无返回值。通过副作用将块号注册到日志头并更新缓存管理状态。
    ///
    /// # 可能的错误
    /// - 若日志空间不足（`LOGSIZE` 或 `self.size` 超限），将触发 panic；
    /// - 若 `outstanding` 计数为 0，表示没有活跃事务，也会 panic；
    /// - 使用未初始化或非法 `buf` 可能导致逻辑错误或内存访问问题；
    /// - 若重复记录相同块，函数会无害返回，不会出错。
    ///
    /// # 安全性
    /// 本函数内部调用了 `unsafe` 的 `buf.pin()` 方法，要求调用前：
    /// - 缓冲块是有效且可被缓存管理系统追踪的；
    /// - 调用过程处于已加锁状态，防止并发访问；
    /// 此外，对 `lh.blocknos` 的修改需确保不越界（由空间检查保障）。
    pub fn write(&self, buf: Buf<'_>) {
        let mut guard = self.lock();
        
        if (guard.lh.len+1) as usize >= LOGSIZE || guard.lh.len+1 >= guard.size {
            panic!("log: not enough space for ongoing transactions");
        }
        if guard.outstanding < 1 {
            panic!("log: this log write is out of recording");
        }

        // record the buf's blockno in the log header
        for i in 0..guard.lh.len {
            if guard.lh.blocknos[i as usize] == buf.read_blockno() {
                drop(guard);
                drop(buf);
                return;
            }
        }
        if (guard.lh.len+2) as usize >= LOGSIZE || guard.lh.len+2 >= guard.size {
            panic!("log: not enough space for this transaction");
        }
        unsafe { buf.pin(); }
        let len = guard.lh.len as usize;
        guard.lh.blocknos[len] = buf.read_blockno();
        guard.lh.len += 1;
        drop(guard);
        drop(buf);
    }

    /// 在每次文件系统调用结束时调用，标记日志事务的结束，并在必要时提交日志。
    ///
    /// # 功能说明
    /// 该函数用于结束一次文件系统操作，与 [`begin_op`] 配对使用。
    /// 每次调用将 `outstanding` 计数减少 1；当该计数归零时，说明当前事务中所有操作都已完成，
    /// 此时将触发日志提交流程。事务提交会将缓存在日志中的块写回磁盘原始位置，并清空日志头。
    ///
    /// # 流程解释
    /// 1. 获取日志锁，减少 `outstanding` 计数；
    /// 2. 若此时日志正在提交中，说明出现逻辑错误（开始或结束时重叠），触发 panic；
    /// 3. 如果 `outstanding` 为 0，说明事务中最后一个操作完成：
    ///     - 设置 `committing` 为 `true`；
    ///     - 暂存当前日志结构体指针，用于解锁后异步提交；
    /// 4. 否则唤醒等待日志空间的其他进程；
    /// 5. 释放日志锁；
    /// 6. 若需提交：
    ///     - 调用 `commit()` 提交日志内容（此时不持锁）；
    ///     - 再次加锁并将 `committing` 标志清除；
    ///     - 唤醒其他等待中的进程；
    ///     - 解锁。
    ///
    /// # 参数
    /// 无参数。调用者为 `SpinLock<Log>` 实例，表示当前日志系统。
    ///
    /// # 返回值
    /// 无返回值。通过副作用完成事务计数管理与日志提交。
    ///
    /// # 可能的错误
    /// - 若在日志提交过程中再次调用 `end_op()`，将触发 panic；
    /// - 若对 `log_ptr` 解引用错误，可能引发未定义行为（由提交条件确保其合法性）；
    /// - 若缺乏正确的 begin/end 配对调用，可能导致逻辑不一致；
    /// - 依赖 `wakeup` 唤醒机制的正确性，否则可能出现永久阻塞。
    ///
    /// # 安全性
    /// 函数中使用了 `unsafe` 来解引用 `log_ptr` 并调用 `commit()`，要求调用路径满足以下条件：
    /// - 在 `outstanding == 0` 时才设置 `committing = true` 并执行提交；
    /// - 所有锁在调用 `commit()` 前已释放，避免潜在死锁；
    /// - 提交后恢复状态并唤醒其他阻塞线程，确保系统正常运行。
    pub fn end_op(&self) {
        let mut log_ptr: *mut Log = ptr::null_mut();

        let mut guard = self.lock();
        guard.outstanding -= 1;
        if guard.committing {
            // it is not allowed to start a fs op while the log is commiting
            panic!("log: end fs op while the log is committing");
        }
        if guard.outstanding == 0 {
            guard.committing = true;
            log_ptr = guard.deref_mut() as *mut Log;
        } else {
            let channel = guard.deref() as *const Log as usize;
            unsafe { PROC_MANAGER.wakeup(channel); }
        }
        drop(guard);

        if !log_ptr.is_null() {
            // SAFETY: Call commit without holding any lock.
            //        And the committing flag protects the log op.
            unsafe { log_ptr.as_mut().unwrap().commit(); }
            let mut guard = self.lock();
            guard.committing = false;
            let channel = guard.deref() as *const Log as usize;
            unsafe { PROC_MANAGER.wakeup(channel); }
            drop(guard);
        }
    }
}

/// 日志头结构体，记录当前事务中被修改的磁盘块信息。
///
/// `LogHeader` 是日志系统的核心元数据之一，用于在内存与磁盘中表示一次事务涉及的所有块号。
/// 它被存储在日志区域的第一个块（即 `start` 块）中，在系统崩溃恢复或日志提交时使用。
/// 日志系统通过该结构判断当前是否存在活跃事务，以及哪些块需要被提交或回滚。
#[repr(C)]
struct LogHeader {
    /// 当前事务中记录的块数量（即 `blocknos` 数组中有效元素的数量）。
    len: u32,

    /// 被当前事务修改的磁盘块号数组。
    /// 这些块会被写入日志区域，并在提交或恢复时依此写回原位置。
    /// 总共最多可容纳 `LOGSIZE - 1` 个块号，保留一个块用于存放该日志头本身。
    blocknos: [u32; LOGSIZE - 1],
}
