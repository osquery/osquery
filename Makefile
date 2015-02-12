PLATFORM := $(shell uname -s)
MAKE = make
ifeq ($(PLATFORM),Darwin)
	BUILD_DIR=darwin
else ifeq ($(PLATFORM),FreeBSD)
	BUILD_DIR=freebsd
	MAKE=gmake
else
	DISTRO := $(shell if [ -f "/etc/redhat-release" ]; then echo "Centos"; fi)
	ifeq ($(DISTRO),Centos)
		BUILD_DIR := $(shell cat /etc/redhat-release | grep -o "release [6-7]" | sed 's/release /centos/g')
	else
    DISTRO := $(shell if [ -f "/etc/lsb-release" ]; then echo "Ubuntu"; fi)
    BUILD_DIR := $(shell lsb_release -sc)
	endif
endif

all: .setup
	cd build/$(BUILD_DIR) && cmake ../.. && \
		$(MAKE) --no-print-directory $(MAKEFLAGS)

debug: .setup
	cd build/$(BUILD_DIR) && DEBUG=True cmake ../../ && \
		$(MAKE) --no-print-directory $(MAKEFLAGS)

test_debug: .setup
	cd build/$(BUILD_DIR)/sdk && DEBUG=True cmake ../../../ && \
	  $(MAKE) test --no-print-directory $(MAKEFLAGS)

analyze: .setup
	cd build/$(BUILD_DIR) && ANALYZE=True cmake ../../ && \
	  $(MAKE) --no-print-directory $(MAKEFLAGS)

sanitize: .setup
	cd build/$(BUILD_DIR) && SANITIZE=True cmake ../../ && \
	  $(MAKE) --no-print-directory $(MAKEFLAGS)

sdk: .setup
	cd build/$(BUILD_DIR)/sdk && SDK=True cmake ../../../ && \
	  $(MAKE) --no-print-directory $(MAKEFLAGS)

test_sdk: .setup
	cd build/$(BUILD_DIR)/sdk && SDK=True cmake ../../../ && \
	  $(MAKE) test --no-print-directory $(MAKEFLAGS)

deps: .setup
	./tools/provision.sh build build/$(BUILD_DIR)

distclean:
	rm -rf .sources build/$(BUILD_DIR) doxygen/html doxygen/latex
ifeq ($(PLATFORM),Linux)
		rm -rf build/linux
endif

.setup:
	mkdir -p build/$(BUILD_DIR)/generated
	mkdir -p build/$(BUILD_DIR)/sdk/generated
ifeq ($(PLATFORM),Linux)
		ln -snf $(BUILD_DIR) build/linux
endif

package:
	# Alias for packages (do not use CPack)
	cd build/$(BUILD_DIR) && cmake ../../ && \
		$(MAKE) packages --no-print-directory $(MAKEFLAGS)

%::
	cd build/$(BUILD_DIR) && cmake ../.. && $(MAKE) --no-print-directory $@
