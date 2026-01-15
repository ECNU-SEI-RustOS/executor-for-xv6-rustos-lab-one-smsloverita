KERNEL = target/riscv64gc-unknown-none-elf/debug/xv6-rust
USER = user
INCLUDE = include
CPUS = 3

CC = riscv64-unknown-elf-gcc
LD = riscv64-unknown-elf-ld
OBJCOPY = riscv64-unknown-elf-objcopy
OBJDUMP = riscv64-unknown-elf-objdump

CFLAGS = -Wall -Werror -O -fno-omit-frame-pointer -ggdb
CFLAGS += -Wno-infinite-recursion
CFLAGS += -MD
CFLAGS += -mcmodel=medany
CFLAGS += -ffreestanding -fno-common -nostdlib -mno-relax
CFLAGS += -I.
CFLAGS += $(shell $(CC) -fno-stack-protector -E -x c /dev/null >/dev/null 2>&1 && echo -fno-stack-protector)

# Disable PIE when possible (for Ubuntu 16.10 toolchain)
ifneq ($(shell $(CC) -dumpspecs 2>/dev/null | grep -e '[^f]no-pie'),)
CFLAGS += -fno-pie -no-pie
endif
ifneq ($(shell $(CC) -dumpspecs 2>/dev/null | grep -e '[^f]nopie'),)
CFLAGS += -fno-pie -nopie
endif

LDFLAGS = -z max-page-size=4096

QEMU = qemu-system-riscv64
QEMUOPTS = -machine virt -bios none -kernel $(KERNEL) -m 3G -smp $(CPUS) -nographic
QEMUOPTS += -drive file=fs.img,if=none,format=raw,id=x0 -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0

GDBPORT = $(shell expr `id -u` % 5000 + 25000)
QEMUGDB = $(shell if $(QEMU) -help | grep -q '^-gdb'; \
	then echo "-gdb tcp::$(GDBPORT)"; \
	else echo "-s -p $(GDBPORT)"; fi)

$(KERNEL):
	cargo build

qemu: $(KERNEL) fs.img
	$(QEMU) $(QEMUOPTS)

.gdbinit: .gdbinit.tmpl-riscv
	sed "s/:1234/:$(GDBPORT)/" < $^ > $@

qemu-gdb: $(KERNEL) .gdbinit fs.img
	@echo "*** Now run 'gdb' in another window." 1>&2
	$(QEMU) $(QEMUOPTS) -S $(QEMUGDB)

asm: $(KERNEL)
	$(OBJDUMP) -S $(KERNEL) > kernel.S

clean:
	rm -rf kernel.S
	cargo clean
	rm -f $(USER)/*.o $(USER)/*.d $(USER)/*.asm $(USER)/*.sym \
	$(USER)/initcode $(USER)/initcode.out fs.img \
	mkfs/mkfs .gdbinit xv6.out* \
	$(USER)/usys.S \
	$(UPROGS)

$(USER)/initcode: $(USER)/initcode.S
	$(CC) $(CFLAGS) -march=rv64g -nostdinc -I. -Iinclude -c $(USER)/initcode.S -o $(USER)/initcode.o
	$(LD) $(LDFLAGS) -N -e start -Ttext 0 -o $(USER)/initcode.out $(USER)/initcode.o
	$(OBJCOPY) -S -O binary $(USER)/initcode.out $(USER)/initcode
	$(OBJDUMP) -S $(USER)/initcode.o > $(USER)/initcode.asm

ULIB = $(USER)/ulib.o $(USER)/usys.o $(USER)/printf.o $(USER)/umalloc.o

_%: %.o $(ULIB)
	$(LD) $(LDFLAGS) -N -e main -Ttext 0 -o $@ $^
	$(OBJDUMP) -S $@ > $*.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $*.sym

$(USER)/usys.S : $(USER)/usys.pl
	perl $(USER)/usys.pl > $(USER)/usys.S

$(USER)/usys.o : $(USER)/usys.S
	$(CC) $(CFLAGS) -c -o $(USER)/usys.o $(USER)/usys.S

$(USER)/_forktest: $(USER)/forktest.o $(ULIB)
	# forktest has less library code linked in - needs to be small
	# in order to be able to max out the proc table.
	$(LD) $(LDFLAGS) -N -e main -Ttext 0 -o $(USER)/_forktest $(USER)/forktest.o $(USER)/ulib.o $(USER)/usys.o
	$(OBJDUMP) -S $(USER)/_forktest > $(USER)/forktest.asm

mkfs/mkfs: mkfs/mkfs.c $(INCLUDE)/fs.h $(INCLUDE)/param.h
	gcc -Werror -Wall -I. -o mkfs/mkfs mkfs/mkfs.c

print-gdbport:
	@echo $(GDBPORT)

# Prevent deletion of intermediate files, e.g. cat.o, after first build, so
# that disk image changes after first build are persistent until clean.  More
# details:
# http://www.gnu.org/software/make/manual/html_node/Chained-Rules.html
.PRECIOUS: %.o

UPROGS=\
	$(USER)/_cat\
	$(USER)/_echo\
	$(USER)/_forktest\
	$(USER)/_grep\
	$(USER)/_init\
	$(USER)/_kill\
	$(USER)/_ln\
	$(USER)/_ls\
	$(USER)/_mkdir\
	$(USER)/_rm\
	$(USER)/_sh\
	$(USER)/_stressfs\
	$(USER)/_usertests\
	$(USER)/_grind\
	$(USER)/_wc\
	$(USER)/_zombie\
    $(USER)/_trace\

fs.img: mkfs/mkfs README $(UPROGS)
	mkfs/mkfs fs.img README $(UPROGS)

-include user/*.d

grade:
	@echo $(MAKE) clean
	@$(MAKE) clean || \
          (echo "'make clean' failed.  HINT: Do you have another running instance of xv6?" && exit 1)
	./grade-lab