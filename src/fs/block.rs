//! disk block operations
//! include bitmap and inode block

use core::ptr;

use bit_field::BitField;

use crate::consts::fs::BPB;

use super::{BCACHE, superblock::SUPER_BLOCK, LOG};
use super::inode::{DiskInode, InodeType, locate_inode_offset};

/// 尝试从文件系统的位图中分配一个空闲的磁盘块，并将该块内容清零后返回其块号。
/// 
///  # 功能说明
/// 尝试从文件系统的位图中分配一个空闲的磁盘块，并将该块内容清零后返回其块号。  
/// 该函数在文件系统位图（bitmap）中查找一个尚未分配的数据块，将其标记为已使用，
/// 并将对应磁盘块内容清零（填充为0）。  
/// 若成功，返回该块的块号；若无法找到可用块，则触发 panic。  
/// 本函数在块分配时使用日志记录机制，确保文件系统的一致性。
///
/// # 流程解释
/// 1. 获取文件系统的总块数，并按照 BPB（每个 bitmap block 能管理的块数）进行分块迭代。  
/// 2. 对于每个 bitmap block，读取其内容后遍历其中每一个 bit：  
///    - 若该 bit 为 0（表示空闲），将其置为 1 并记录写入日志。  
///    - 然后读取实际的数据块，对其内容进行清零操作，并再次写入日志。  
///    - 返回该块号作为成功分配的结果。  
/// 3. 若全部 bitmap block 检查完仍未找到空闲块，则触发 panic。
///
/// # 参数
/// - `dev: u32`：设备号，表示在哪个设备上进行块分配操作。
///
/// # 返回值
/// - `u32`：成功分配并清零的磁盘块号。
///
/// # 可能的错误
/// - 若文件系统中不存在任何空闲块，则触发 panic：`"bitmap: cannot alloc any free block"`。  
/// - 若 bitmap block 或数据块的读取失败（依赖于 `BCACHE.bread` 的内部实现），可能引发未定义行为（本函数不显式处理 IO 错误）。
///
/// # 安全性
/// - 使用了多处 `unsafe` 操作，包括原始指针偏移与字节操作。需确保：  
///   - `buf.raw_data_mut()` 返回的指针有效且指向合法内存区域；  
///   - 偏移 `index` 后的指针仍在有效范围内。  
/// - 所有内存写入（例如使用 `ptr::write_bytes` 清零）必须保证目标地址对应的是已成功读取并锁定的磁盘块缓冲区。  
/// - 日志写入 `LOG.write()` 要求调用者持有一致性的写入上下文。

pub fn bm_alloc(dev: u32) -> u32 {
    // first, iterate each bitmap block
    let total_block = unsafe { SUPER_BLOCK.size() };
    for base in (0..total_block).step_by(BPB as usize) {
        let mut buf = BCACHE.bread(dev, unsafe { SUPER_BLOCK.bitmap_blockno(base) });
        // second, iterate each bit in the bitmap block
        for offset in 0..BPB {
            if base + offset >= total_block {
                break;
            }
            let index = (offset / 8) as isize;
            let bit = (offset % 8) as usize;
            let byte = unsafe { (buf.raw_data_mut() as *mut u8).offset(index).as_mut().unwrap() };
            if byte.get_bit(bit) {
                continue;
            }
            byte.set_bit(bit, true);
            LOG.write(buf);

            // zero the free block
            let free_bn = base + offset;
            let mut free_buf = BCACHE.bread(dev, free_bn);
            unsafe { ptr::write_bytes(free_buf.raw_data_mut(), 0, 1); }
            LOG.write(free_buf);
            return free_bn
        }
        drop(buf);
    }

    panic!("bitmap: cannot alloc any free block");
}

/// # 功能说明
/// 释放一个磁盘块，通过将位图中对应位设置为 0，标记该块为空闲状态。  
/// 该函数用于回收磁盘块资源，使其可被后续的 `bm_alloc` 再次分配使用。
///
/// # 流程解释
/// 1. 根据给定的块号 `blockno`，计算出该块在位图中的 bitmap block 编号 `bm_blockno`。  
/// 2. 通过 `BCACHE.bread` 读取对应的 bitmap block。  
/// 3. 计算该块在 bitmap 中的偏移位置（字节索引和 bit 索引）。  
/// 4. 获取该字节并检查其 bit 是否为 1（已被分配），若不是则触发 panic（防止重复释放）。  
/// 5. 将该 bit 位置为 0（表示空闲），并记录该修改到日志中。
///
/// # 参数
/// - `dev: u32`：设备号，表示在哪个设备上释放块。  
/// - `blockno: u32`：要释放的磁盘块号。
///
/// # 返回值
/// 无返回值。该函数通过副作用更新位图状态并记录日志。
///
/// # 可能的错误
/// - 若释放一个未被分配的块（即位图中对应位已为 0），会触发 panic：`"bitmap: double freeing a block"`。  
/// - 若 bitmap block 的读取或写入失败（依赖于 `BCACHE.bread` 和 `LOG.write` 的实现），可能导致未定义行为，但函数本身未显式处理这些错误。
///
/// # 安全性
/// - 使用了 `unsafe` 操作来对 bitmap 缓冲区内存执行原始指针偏移和修改：  
///   - `buf.raw_data_mut()` 返回的指针必须合法；  
///   - 偏移后的指针需确保在 bitmap block 的有效范围内，防止越界访问。  
/// - 位图操作依赖于精确的块号与位偏移计算，若 `blockno` 非法或越界，可能破坏 bitmap 状态。  
/// - 调用者需保证该块号确实已分配过，避免违反释放前置条件。

pub fn bm_free(dev: u32, blockno: u32) {
    let bm_blockno = unsafe { SUPER_BLOCK.bitmap_blockno(blockno) };
    let bm_offset = blockno % BPB;
    let index = (bm_offset / 8) as isize;
    let bit = (bm_offset % 8) as usize;
    let mut buf = BCACHE.bread(dev, bm_blockno);
    
    let byte = unsafe { (buf.raw_data_mut() as *mut u8).offset(index).as_mut().unwrap() };
    if !byte.get_bit(bit) {
        panic!("bitmap: double freeing a block");
    }
    byte.set_bit(bit, false);
    LOG.write(buf);
}

/// # 功能说明
/// 在磁盘或文件系统中分配一个空闲的 inode，并初始化其类型，返回对应的 inode 编号。  
/// 若 inode 表已满，则触发 panic。该函数是文件或目录创建操作的基础步骤之一。
///
/// # 流程解释
/// 1. 读取超级块中的 inode 总数。  
/// 2. 从编号 1 开始（跳过编号 0 的保留 inode）依次遍历所有 inode：  
///    - 通过 `SUPER_BLOCK.locate_inode(inum)` 获取该 inode 所在的磁盘块号；  
///    - 通过 `locate_inode_offset(inum)` 获取在块内的偏移位置；  
///    - 读取对应的磁盘块，并在内存中定位到该 inode 结构。  
/// 3. 尝试调用 `DiskInode::try_alloc` 对其分配指定类型的 inode（如文件、目录等）；  
///    - 若分配成功，则将修改后的块写入日志系统，并返回该 inode 编号；  
///    - 若失败（表示该 inode 已被占用），则跳过继续尝试下一个。
/// 4. 若全部 inode 都被占用，则最终触发 panic。
///
/// # 参数
/// - `dev: u32`：设备号，表示在哪个设备上分配 inode。  
/// - `itype: InodeType`：要分配的 inode 类型，例如普通文件或目录。
///
/// # 返回值
/// - `u32`：成功分配的 inode 编号。
///
/// # 可能的错误
/// - 若没有可用的 inode，将触发 panic：`"not enough inode to alloc"`。  
/// - 若 `SUPER_BLOCK` 提供的 inode 元信息错误，可能导致越界或非法访问（依赖其正确性）。
///
/// # 安全性
/// - 使用了 `unsafe` 操作来执行原始指针偏移和类型转换：  
///   - `buf.raw_data_mut()` 返回的指针必须合法，并具有 `DiskInode` 所需的内存对齐与长度；  
///   - `offset()` 计算应确保不越界，且 `DiskInode` 写入必须不会破坏其他结构体。  
/// - 若 `try_alloc` 未能正确标记 inode 状态，可能导致后续文件系统状态异常。  
/// - 调用者需确保并发安全（例如需要锁保护 inode 表的写操作），否则可能出现重复分配。
pub fn inode_alloc(dev: u32, itype: InodeType) -> u32 {
    let size = unsafe { SUPER_BLOCK.inode_size() };
    for inum in 1..size {
        let blockno = unsafe { SUPER_BLOCK.locate_inode(inum) };
        let offset = locate_inode_offset(inum);
        let mut buf = BCACHE.bread(dev, blockno);
        let dinode = unsafe { (buf.raw_data_mut() as *mut DiskInode).offset(offset) };
        let dinode = unsafe { &mut *dinode };
        if dinode.try_alloc(itype).is_ok() {
            LOG.write(buf);
            return inum
        }
    }

    panic!("not enough inode to alloc");
}
