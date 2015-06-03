# OS X kext makefile
VERSION:=$(shell git describe --tags HEAD --always)
VERSION_DEFINE:=-DVERSION="\"$(VERSION)\""

CC:=clang
CXX:=clang++

# Directories
INCLUDE_DIR:=include/
BUILD_DIR:=build/
SOURCE_DIR:=src/
KEXT:=osquery.kext
CONTENTS_DIR:=$(BUILD_DIR)$(KEXT)/Contents/
OUTPUT_DIR:=$(CONTENTS_DIR)MacOS/
RUNDIR:=/tmp/
USER_DIR:=user/

INCLUDES:=$(wildcard $(INCLUDE_DIR)*.h)
INCLUDE:=-I$(INCLUDE_DIR) -I/System/Library/Frameworks/Kernel.framework/Headers
FLAGS:=-arch x86_64 -mkernel
CXXFLAGS:=$(FLAGS) -nostdinc -fno-builtin $(INCLUDE) $(VERSION_DEFINE)
CFLAGS:=$(FLAGS) -nostdinc -fno-builtin $(INCLUDE) $(VERSION_DEFINE)
LDFLAGS:=$(FLAGS) -Xlinker -kext -nostdlib -lkmod
CSOURCES:=$(wildcard $(SOURCE_DIR)*.c)
CXXSOURCES:=$(wildcard $(SOURCE_DIR)*.cpp)
SOURCES:=$(CSOURCES) $(CXXSOURCES)
OBJECTS:=$(addprefix $(BUILD_DIR), $(notdir $(CXXSOURCES:.cpp=.cpp.o))) \
	$(addprefix $(BUILD_DIR), $(notdir $(CSOURCES:.c=.c.o)))
OUTPUT:=$(BUILD_DIR)output
EXECUTABLE:=$(OUTPUT_DIR)osquery
DSYM:=$(EXECUTABLE).dSYM
BUNDLE_PLIST:=Info.plist

# Can use the kernel suffix development to load the development kernel.  You
# have to reconfigure the target after changing the suffix.
KERNEL_SUFFIX:=
ifeq ($(KERNEL_SUFFIX),)
  KERNEL:=kernel
else
  KERNEL:=kernel.$(KERNEL_SUFFIX)
endif
ifeq ($(KERNEL_SUFFIX),developement)
  NVRAM_FLAGS:=-v pmuflags=1
else
  NVRAM_FLAGS:=-v
endif
DEV_KERNEL:=/System/Library/Kernels/$(KERNEL)

.PHONY: all
all:  $(EXECUTABLE)

.PHONY: debug
debug: CXXFLAGS+= -DDEBUG -g
debug: CFLAGS+= -DDEBUG -g
debug: LDFLAGS+= -DDEBUG -g
debug: $(DSYM)

.PHONY: release
release: CXXFLAGS+= -O3
release: CCFLAGS+= -O3
release: LDFLAGS+= -O3
release: $(EXECUTABLE)
	strip -S $<

# For building and running tests.  Not debugging.  Disables signature checks!
.PHONY: test
test:   disable-signing
	sudo ./test.sh $(BUILD_DIR)consumer.out $(BUILD_DIR)producer.out 5 && \
	echo "Test success!"

$(OUTPUT):
	mkdir -p $(OUTPUT_DIR) &&\
	touch $(OUTPUT)

$(CONTENTS_DIR)$(BUNDLE_PLIST):
	cp $(SOURCE_DIR)$(BUNDLE_PLIST) $(CONTENTS_DIR)

$(BUILD_DIR)%.cpp.o: $(SOURCE_DIR)%.cpp $(INCLUDES) $(OUTPUT)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)%.c.o: $(SOURCE_DIR)%.c $(INCLUDES) $(OUTPUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(EXECUTABLE): $(OBJECTS) $(OUTPUT) $(CONTENTS_DIR)$(BUNDLE_PLIST)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@

$(RUNDIR)$(KEXT): $(EXECUTABLE) $(OUTPUT) $(CONTENTS_DIR)$(BUNDLE_PLIST)
	sudo cp -rp ./$(BUILD_DIR)$(KEXT) $(RUNDIR) && \
	sudo chown -R root:wheel $(RUNDIR)$(KEXT) && \
	sudo chmod -R 0644 $(RUNDIR)$(KEXT)

$(DSYM): $(EXECUTABLE)
	dsymutil $< -o $@ && strip -S $<

.PHONY: clean
clean:
	sudo rm -rf -- $(BUILD_DIR)* $(RUNDIR)$(KEXT)

$(DEV_KERNEL):
	sudo cp /Library/Developer/KDKs/*/System/Library/Kernels/$(KERNEL) \
	  /System/Library/Kernels/


# Load the compiled kext.  If debugging make sure kext was compiled on the host
# machine to get source level debugging.
.PHONY: load
load:  $(RUNDIR)$(KEXT)
	sudo kextload -v $(RUNDIR)$(KEXT)

# Unload the kext.
.PHONY: unload
unload:
	sudo kextunload -v $(RUNDIR)$(KEXT)

# Return boot arguments to default.  Used to turn back on signature checks and
# disable dev kernel nvram flags.
.PHONY: restore-target clear-boot-args
restore-target clear-boot-args:
	sudo nvram -d boot-args && echo 'REBOOT REQUIRED'

###################################################
#
# Build and load on own machine (CAUTION).
#
##################################################
# - If kext is not signed disable signature checks (disable-signing target).
# - Run the load target.  This will compile and load a non debug version of
#   the kext.

# Stops kernel extension signatures from being checked before they are loaded.
# configure-target disables signing as well
.PHONY: disable-signing
disable-signing:
	sudo nvram boot-args=kext-dev-mode=1 && echo 'REBOOT REQUIRED'

###################################################
#
# Debugging environment setup.
#
###################################################
# - Create a VM to act as the target machine.
# - Make this directory a shared folder between host and VM.
# - Get a kernel debug kit from:
#       https://developer.apple.com/downloads/
# - Install it on both the target machine VM and the host debugging machine.
# - Run make targets to configure the target machine and the debugger machine.
#       - configure-target   (on VM, requires a reboot)
#       - configure-debugger (on host)
# - Launch debugger on host using the db target this loads the kernel symbols
#   and commands.
# - Connect to VM using the kdp-remote command.
# - Once the VM is booted ssh in and load the kext by running the load target.

# This target configuration does:
#    Disables signature checking and sets OS X into kernel debug mode.
#    if KERNEL_SUFFIX is set to development:
#      OS X will not check PMU unit.
#      OS X will boot development kernel (better have it installed from kernel
#        debug kit).
#    OS X will wait for a network debugger to attach at boot.
#    OS X will not display panic dialogs
#    OS X will interrupt when sent a cntrl + opt + cmd + shift + esc
BOOT_ARGS:=$(NVRAM_FLAGS) kcsuffix=$(KERNEL_SUFFIX) kext-dev-mode=1 debug=0x14F
.PHONY: configure-target kernel-debug
configure-target kernel-debug: $(DEV_KERNEL)
	sudo nvram boot-args="$(BOOT_ARGS)" \
	&& echo 'REBOOT REQUIRED'

# This debugger configuration does:
#    Make debugging machine allow LLDB commands to be loaded from symbol files.
#    In this case it is to allow it to load commands fromt the kernel symbol
#    file.
.PHONY: configure-debugger
configure-debugger:
	touch ~/.lldbinit && \
	(grep -q -F 'settings set target.load-script-from-symbol-file true' \
	  ~/.lldbinit \
	|| echo "settings set target.load-script-from-symbol-file true" \
	  >> ~/.lldbinit)

# Compile debug and launch debugger.  Launch a congfigured target VM and attach
# to it using kdp-remote once booted.  Load the kext using make load on the
# target VM.  (NOTE build on debugging machine for source level debugging).
.PHONY: db
db:
	make -p build && \
	cd build && \
	lldb /Library/Developer/KDKs/*/System/Library/Kernels/$(KERNEL)

# Determine the libraries that are needed to be inclduded in the Info.plist
# file.
.PHONY: libs
libs:  $(RUNDIR)$(KEXT)
	sudo kextlibs $(RUNDIR)$(KEXT)


