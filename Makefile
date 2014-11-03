PLATFORM := $(shell uname -s)
ifeq ($(PLATFORM),Darwin)
	BUILD_DIR=darwin
else
	DISTRO := $(shell if [ -f "/etc/redhat-release" ]; then echo "Centos"; fi)
	ifeq ($(DISTRO),Centos)
		BUILD_DIR=centos
	else
		BUILD_DIR=ubuntu
	endif
endif

all:
	mkdir -p build/$(BUILD_DIR)
	$(if $(PLATFORM) == Linux, ln -snf $(BUILD_DIR) build/linux)
	cd build/$(BUILD_DIR) && cmake ../.. && make --no-print-directory $(MAKEFLAGS)

debug:
	mkdir -p build/$(BUILD_DIR)
	$(if $(PLATFORM) == Linux, ln -snf $(BUILD_DIR) build/linux)
	cd build/$(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=Debug ../../ && \
		make --no-print-directory $(MAKEFLAGS)

deps:
	./tools/provision.sh

distclean:
	rm -rf .sources build/$(BUILD_DIR) doxygen/html doxygen/latex
	$(if $(PLATFORM) == Linux, rm -rf build/linux)

%::
	mkdir -p build/$(BUILD_DIR)
	$(if $(PLATFORM) == Linux, ln -snf $(BUILD_DIR) build/linux)
	cd build/$(BUILD_DIR) && cmake ../.. && make --no-print-directory $@
