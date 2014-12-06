obj-m += camb.o
camb-objs += main.o sysfs.o hash.o

# We need headers to build against a specific kernel version
ifndef KDIR
  KDIR = /lib/modules/$(shell uname -r)/build
#  @echo "Using default kernel directory: ${KDIR}"
endif

# If user specifies a System.map, get addresses from there
ifdef SMAP
  OPTS += -DTEXT_SEGMENT_START="0x$(shell grep '\s\+T\s\+_stext\b' ${SMAP} | cut -f1 -d' ')"
  OPTS += -DTEXT_SEGMENT_END="0x$(shell grep '\s\+T\s\+_etext\b' ${SMAP} | cut -f1 -d' ')"
  OPTS += -DSYSCALL_BASE_ADDR="0x$(shell grep '\s\+R\s\+sys_call_table\b' ${SMAP} | cut -f1 -d' ')"

# Otherwise, they must be present on the build line 
else
  OPTS += -DTEXT_SEGMENT_START="${TEXT_SEGMENT_START}"
  OPTS += -DTEXT_SEGMENT_END="${TEXT_SEGMENT_END}"
  OPTS += -DSYSCALL_BASE_ADDR="${SYSCALL_BASE_ADDR}"
endif

ifdef HIDE_ME
  OPTS += -DHIDE_ME
  camb-objs += hide.o
endif

all:

ifndef SMAP
  ifndef TEXT_SEGMENT_START
		@echo "Missing parameter: TEXT_SEGMENT_START"
		@exit 1
  endif

  ifndef TEXT_SEGMENT_END
		@echo "Missing parameter: TEXT_SEGMENT_END"
		@exit 1
  endif

  ifndef SYSCALL_BASE_ADDR
		@echo "Missing parameter: SYSCALL_BASE_ADDR"
		@exit 1
  endif
endif

	$(MAKE) -C $(KDIR) M=$(shell pwd) EXTRA_CFLAGS="${OPTS}" modules
