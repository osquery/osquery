PLATFORM := $(shell uname -s)
ifeq ($(PLATFORM),Darwin)
	BUILD_DIR=build/darwin
else
	BUILD_DIR=build/linux
endif

all:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake ../.. && make --no-print-directory $(MAKEFLAGS)

deps:
	./tools/provision.sh

distclean:
	rm -rf .sources $(BUILD_DIR) doxygen/html doxygen/latex

%::
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake ../.. && make --no-print-directory $@
