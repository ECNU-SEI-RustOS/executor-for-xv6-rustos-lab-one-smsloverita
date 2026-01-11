[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/_4c_3S5F)
# 嵌入式操作系统课程实验手册

## 第一部分：系统调用跟踪（80分）

**实验要求**

在本次实验中，你将为内核添加一个 **系统调用跟踪功能**，这个功能在你调试后续实验时将会非常有帮助。

你需要实现一个新的系统调用：`trace`。该系统调用用于控制追踪行为，它接受一个参数：一个整数类型的“**掩码（mask）**”。这个掩码的每一位代表一个系统调用，若某一位被设置为 1，则表示需要追踪对应编号的系统调用。

例如，若希望追踪 `fork` 系统调用，一个程序可以调用：

```c
trace(1 << SYS_fork);
```

其中，`SYS_fork` 是 `include/syscall.h` 中定义的系统调用编号。

你需要对内核进行修改，使其在每个系统调用即将返回结果时，判断是否需要输出追踪信息。若该系统调用的编号在当前掩码中被设置，则输出一行追踪信息。追踪信息包括：

- 当前进程的 PID（进程号）
- 系统调用的名称
- 返回值

**注意**：你不需要打印系统调用的参数。

此外，`trace` 系统调用只对当前调用它的进程及该进程随后通过 `fork` 创建的子进程生效，对其他进程没有影响。

------

**实验现象**

我们提供了一个名为 `trace` 的用户态程序，用于在启用追踪功能的情况下运行另一个程序（见 `user/trace.c`）。完成实验后，你应该会看到类似如下的输出结果：

```
/* 示例1 */
$ trace 32 grep hello README
2: syscall read -> 1023
2: syscall read -> 966
2: syscall read -> 70
2: syscall read -> 0
/* 示例2 */
$ trace 2147483647 grep hello README
3: syscall trace -> 0
3: syscall exec -> 3
3: syscall open -> 3
3: syscall read -> 1023
3: syscall read -> 966
3: syscall read -> 70
3: syscall read -> 0
3: syscall close -> 0
/* 示例3 */
$ grep hello README
/* 示例4 */
$ trace 2 usertests forkforkfork
usertests starting
5: syscall fork -> 6
test forkforkfork: 5: syscall fork -> 7
7: syscall fork -> 8
8: syscall fork -> 9
8: syscall fork -> 10
9: syscall fork -> 11
8: syscall fork -> 12
10: syscall fork -> 13
......
......
OK
5: syscall fork -> 71
ALL TESTS PASSED
```

在上面的几个示例中，trace 的行为如下：

1. **第一个示例中**，trace 仅追踪了 `read` 系统调用。数字 32 是 `1 << SYS_read` 的结果，表示只追踪编号为 `SYS_read` 的系统调用。
2. **第二个示例中**，trace 运行 grep 时追踪了所有的系统调用。数值 `2147583647` 的二进制形式是低 31 位全为 1，表示开启所有系统调用的追踪。
3. **第三个示例中**，程序未启用追踪功能，因此不会有任何追踪输出。
4. **第四个示例中**，运行 usertests 中的 `forkforkfork` 测试，追踪的是所有子进程中的 `fork` 系统调用。

只要你的程序运行行为与上述描述一致（尽管具体的进程 ID 可能会有所不同），就说明你的实现是正确的。

运行 `make grade` 后看到如下输出，说明你的实现通过了测试。
```
== Test trace 32 grep == trace 32 grep: OK (5.9s) 
== Test trace all grep == trace all grep: OK (0.9s) 
== Test trace nothing == trace nothing: OK 
== Test trace children == trace children: OK (40.1s)
```

------

**实现提示**

1. **在 Makefile 中添加可执行目标**
    在 `Makefile` 中的 `UPROGS` 列表中添加一项：`$(USER)/_trace\`，用于编译用户态的 `trace` 程序。

2. **构建系统调用接口原型**
    运行 `make qemu` 后你会发现系统无法编译 `user/trace.c`，因为你还没有为新的系统调用添加用户态的接口。这部分工作包括：

   - 在 `user/user.h` 中添加 `trace` 的函数声明；
   - 在 `user/usys.pl` 中添加 `trace` 的名字，用于自动生成汇编包装代码；
   - 在 `include/syscall.h` 中为 `trace` 分配一个新的系统调用编号。

   `Makefile` 会调用 `user/usys.pl` 脚本，它会生成 `user/usys.S` 文件，这个文件包含系统调用的用户态包装函数，它们会通过 RISC-V 的 `ecall` 指令切换到内核态。

3. **实现内核中的系统调用处理逻辑**
    修复用户程序编译后，再次运行 `trace 32 grep hello README`，你会发现程序仍然报错，因为此时 `trace` 系统调用尚未在内核中实现。

   - 在 `src/process/proc/syscall.rs` 中添加一个新的 `sys_trace()` 函数；
   - 该函数需要将传入的 `mask` 参数存储到当前进程的 `proc` 结构体中（见 `src/process/proc/mod.rs`），用于后续判断是否追踪；
   - 获取系统调用参数可以调用 `src/process/proc/syscall.rs` 中已有的参数提取函数，具体用法可以参考 `syscall.rs` 中的其他系统调用实现。

4. **在进程派生时复制追踪设置**
    修改 `src/process/proc/mod.rs` 中的 `fork()` 实现，使得父进程的追踪掩码能正确地复制给子进程。

5. **在 syscall 分发函数中实现打印逻辑**
    修改 `src/process/proc/mod.rs` 中的 `syscall()` 函数，实现在系统调用返回前判断是否启用了追踪，如果是，则打印追踪信息。你需要：

   - 添加一个系统调用名称字符串数组，方便通过系统调用编号进行查找；
   - 在正确的位置打印进程 ID、系统调用名称和返回值等信息。

## 第二部分：打印页表(20分)

**这一部分为附加题，需要你对RISC-V SV39虚拟内存机制具有一定的了解**

**实验要求**

为了帮助你更直观地理解 RISC-V 的页表结构，同时也便于将来的调试工作，你的任务是：**实现一个函数，用于打印当前进程的页表内容**。你需要定义一个名为 `vm_print()` 的函数。该函数接受一个 `pagetable` 类型的参数，并以特定格式打印该页表的内容（格式要求将在后续实验说明中详细介绍）。这个打印函数的目标是清晰地展示虚拟页与物理页的映射关系，以及页表的层次结构。

为验证你的实现，请在 `syscall.rs` 文件中，在`sys_exec`函数的合适位置插入如下代码：

```rust
let guard = self.excl.lock();
if guard.pid == 1 {
    let data = self.data.get_mut();
    data.pagetable.as_ref().unwrap().vm_print(0);
}
drop(guard);
```

这段代码会在第一个用户进程执行时自动打印其页表信息。

只要你能够通过 `make grade` 中与页表打印相关的测试用例（即 `pte printout` 测试），就可以获得该实验部分的**满分**。

------

**实验现象**

现在当你启动时，应该会看到类似如下的输出，描述的是**第一个进程在刚刚完成 `sys_exec()` 调用后**的页表内容：

```
page table 0x803fd000
..0: pte 0x200fec01 pa 0x803fb000
.. ..0: pte 0x200ff001 pa 0x803fc000
.. .. ..0: pte 0x200fe85f pa 0x803fa000
.. .. ..1: pte 0x20101c0f pa 0x80407000
.. .. ..2: pte 0x201020df pa 0x80408000
..255: pte 0x20101801 pa 0x80406000
.. ..511: pte 0x200fe401 pa 0x803f9000
.. .. ..510: pte 0x200fe0c7 pa 0x803f8000
.. .. ..511: pte 0x2000044b pa 0x80001000
```

打印输出的第一行显示的是当前即页表的起始地址。随后每一行对应一个有效的页表项（PTE），包括那些指向更深层级页表页的中间页表项。

每一行页表项之前会有若干个 `" .."` 缩进，缩进的数量表示该页表项所在页表在页表树中的层级深度（顶层为 0，越往下层缩进越多）。

每一行页表项的输出内容包括：

- 该页表项在当前页表页中的索引；
- 页表项的控制位（如有效位、用户位、读写权限等）；
- 从页表项中提取出的物理页地址。

注意：**不要打印无效的页表项**（即 `valid` 位未置位的 PTE）。

在上面的输出示例中，顶层页表页中映射了第 0 项和第 255 项；对于第 0 项指向的下一级页表中，仅第 0 项被映射；而该页表中的第 0 项再进一步指向底层页表，其中第 0, 1, 2 项被映射。

你实现的代码可能会打印出与示例中不同的物理地址，但映射的项数以及它们对应的虚拟地址索引应当是一致的。

------

**实验提示**

- 你可以将 `vm_print()` 函数的实现放在 `mm/pagetable.rs` 文件中，作为`PageTable`结构体的一个成员函数；
- `vm_print()` 函数可以采用递归或循环的方式实现，根据你实现的不同可以修改函数的参数列表；
  - 若采用递归实现，函数参数中应当包含当前递归的层数；
  - 若采用循环实现，请去除在`sys_exec`函数中添加的代码中`vm_print()`的参数；
- 在实现过程中，可以使用`PageTableEntry`的`as_page_table`方法来帮助你简化一些繁琐的位操作；
- 可以参考函数 `walk` 的实现思路，它同样用于遍历多级页表结构；
- 在Rust的`println`宏中使用`{:x}`打印十六进制数；


## xv6-rust 实验平台操作说明

本实验指导手册基于Rust语言开发的类xv6架构操作系统内核编写。下面介绍实验平台以及系统内核的操作方法，请根据说明进行模仿，确保执行的结果与说明一致。

### 实验平台操作方法

实验平台的操作通过Makefile实现，下面介绍本实验平台的Makefile允许执行的操作：

**`make qemu`**

- 该指令用于启动内核，执行用户程序与内核进行交互
- 执行该指令后，将会自动编译系统内核，用户程序，并生成初始化文件系统，最终启动QEMU
- 本指令不会检测到内核代码的修改，对内核代码进行修改后，请先执行`make clean`

正确执行该指令后应该看到如下输出

```
qemu-system-riscv64 -machine virt -bios none -kernel target/riscv64gc-unknown-none-elf/debug/xv6-rust -m 3G -smp 3 -nographic -drive file=fs.img,if=none,format=raw,id=x0 -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0

xv6-rust is booting

KernelHeap: available physical memory [0x80054028, 0x88000000)
  buddy system: useful memory is 0x7fab000 bytes
  buddy system: leaf size is 16 bytes
  buddy system: free lists have 24 different sizes
  buddy system: alloc 0x300490 bytes meta data
  buddy system: 0x55000 bytes unavailable
KernelHeap: init memory done
hart 2 starting
hart 1 starting
file system: checking logs
file system: no need to recover
file system: setup done
init: starting sh
$ 
```

**`make qemu-gdb`**

- 该指令用于调试内核，首先启动QEMU并等待GDB连接，连接成功后按照GDB的指令运行内核
- 首先开启两个终端，在第一个终端中执行该指令，等待内核编译完成后启动QEMU

QEMU启动后输出如下

```
*** Now run 'gdb' in another window.
qemu-system-riscv64 -machine virt -bios none -kernel target/riscv64gc-unknown-none-elf/debug/xv6-rust -m 3G -smp 3 -nographic -drive file=fs.img,if=none,format=raw,id=x0 -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -S -gdb tcp::26000
```

- 在第二个终端中执行`gdb-multiarch`（或任何可用的gdb），待gdb启动后执行`source .gdbinit`

此时GDB窗口输出如下

```
GNU gdb (Ubuntu 12.1-0ubuntu1~22.04.2) 12.1
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
...
(gdb) source .gdbinit
The target architecture is set to "riscv:rv64".
warning: No executable has been specified and target does not support
determining executable automatically.  Try using the "file" command.
0x0000000000001000 in ?? ()
(gdb) 
```

至此，QEMU与GDB连接成功，可以在GDB中执行调试指令以运行内核，具体调试办法详见**内核调试方法**

**`make asm`**

- 该指令会执行objdump对内核进行反汇编，输出内核的汇编指令
- 输出结果在kernel.S文件中，其中主要包含函数名称，指令地址以及指令内容
- 可用于内核异常时根据异常指令地址定位出错函数

以系统启动位置的汇编代码为例，该文件结构如下

```assembly
0000000080000000 <_entry>:
    80000000:	0002c117          	auipc	sp,0x2c
    80000004:	00010113          	mv		sp,sp
    80000008:	6509                lui		a0,0x2
    8000000a:	f14025f3          	csrr	a1,mhartid
    8000000e:	0585                addi	a1,a1,1
    80000010:	02b50533          	mul		a0,a0,a1
    80000014:	912a                add		sp,sp,a0
    80000016:	00001097          	auipc	ra,0x1
    8000001a:	114080e7          	jalr	276(ra) # 8000112a <start>
```

**`make clean`**

- 该指令将清空所有编译结果，将实验环境初始化
- 包括用户程序编译结果，内核编译结果，文件系统镜像
- 同时还会清除`make asm`生成的反汇编结果

运行后将执行如下指令

```bash
rm -rf kernel.S
cargo clean
rm -f user/*.o user/*.d user/*.asm user/*.sym \
user/initcode user/initcode.out fs.img \
mkfs/mkfs .gdbinit xv6.out \
user/usys.S \
user/_cat user/_echo user/_forktest user/_grep user/_init user/_kill user/_ln user/_ls user/_mkdir user/_rm user/_sh user/_stressfs user/_usertests user/_grind user/_wc user/_zombie user/_sleep user/_pingpong user/_primes user/_find user/_xargs
```

------

### 系统内核操作方法

这里主要介绍两个常用快捷键

- `Ctrl+P`：输出内核中正在运行的进程列表
- `Ctrl+A+X`：停止内核运行，关闭QEMU

在执行`make qemu`后，系统内核会启动，并自动执行shell用户程序，该程序输出一个dollar符号并等待用户选择用户程序进行执行。

shell 是一个非常简洁的用户态程序，它为操作系统提供基本的用户交互接口。在内核中，它的源代码位于 `user/sh.c` 文件，是用户运行的第一个可交互程序。

**命令解析与执行**

- Shell 使用 `fork + exec` 模式执行用户输入的命令。

- 支持内建命令（如 `cd`）和外部程序（如 `ls`, `cat`, `sh`, `echo`）。

- 输入示例：

  ```
  $ echo hello
  $ ls
  ```

- 对于外部程序，shell 会：

  1. `fork` 创建子进程；
  2. 在子进程中调用 `exec` 替换为对应的用户程序；
  3. 父进程 `wait` 直到子进程结束。

**I/O 重定向（< 和 >）**

- 允许将输入或输出重定向到文件。

- 示例：

  ```bash
  $ echo hello > out.txt
  $ cat < out.txt
  ```

- 实现方式：

  - shell 在解析命令时检测 `<` 或 `>`；
  - 使用 `open()` 打开对应文件；
  - 使用 `dup()` 将标准输入（fd=0）或标准输出（fd=1）重定向到该文件描述符。

**管道支持（|）**

- 支持使用 `|` 连接多个命令的输出与输入。

- 示例：

  ```bash
  $ ls | grep usertests
  ```

- 实现方式：

  - shell 创建管道（`pipe(fd)`）；
  - fork 两个子进程，一个写管道，一个读管道；
  - 使用 `dup()` 将 stdout/stdin 重定向为管道端点。

**内建命令：**`cd`

- xv6 shell 支持内建的 `cd` 命令改变当前工作目录。

- 示例：

  ```bash
  $ cd /bin
  ```

- 特殊性：

  - `cd` 不能用 `exec` 实现，因为目录更改必须在当前进程（shell）中生效。
  - 因此，shell 检测到 `cd` 后直接调用 `chdir()` 而不 fork。

------

### 系统内核调试方法

**常用 GDB 调试命令**

1. 显示源码布局

```gdb
layout src
```

- 显示源代码窗口。
- 按 `Ctrl+L` 可刷新界面。
- 使用 `layout split` 可同时显示代码和汇编。

------

2. 设置断点

```gdb
b rust_main
b usertrap
b trap.rs:42
```

- 在指定函数或文件行号设置断点。
- 可以使用 `info break` 查看当前所有断点。
- 使用 `delete` 删除断点。

------

3. 运行与继续执行

```gdb
c        # continue，继续运行直到下一个断点
```

- 如果你设置了断点并执行 `continue`，GDB 会在命中断点时停止。

------

4. 单步调试

```gdb
s        # step：单步进入函数
n        # next：单步执行，不进入函数
fin      # finish：运行直到当前函数返回
```

- `s`（step）适合函数内部逐行观察。
- `n`（next）在调用函数时会跳过函数体。
- `fin`（finish）会跑到当前函数结束，常用于快速跳出。

------

5. 变量与表达式查看

```gdb
p var_name            # 打印变量值
p/x 0x80000000        # 以十六进制打印值
p *(int*)0x80000000   # 以 C 样式解引用地址
```

- `x/4x`：查看内存，十六进制模式。
- `x/s`：查看字符串内容。
- `display`：持续显示变量。
- `set var foo = 3`：更改变量值。

------

6. 查看调用栈与函数

```gdb
bt       # backtrace：查看调用栈
frame 1  # 切换到栈帧 1
info registers
```

- `bt` 是诊断内核 panic 和 trap 问题的重要工具。
- 可以在每一层 frame 中使用 `list`、`p` 查看局部变量。

------

7. 内核结构调试示例

```gdb
p *myproc       # 查看当前进程结构体
p myproc->trapframe
p myproc->pagetable
```

如果你在 `proc.rs` 等处设置断点并想调试当前 `Proc` 的状态，这种方式非常有用。

------

8. 查看内存

```gdb
x/16x 0x80000000     # 查看从物理地址 0x80000000 开始的 16 个字
x/4i $pc             # 查看当前 PC 附近的指令
```
