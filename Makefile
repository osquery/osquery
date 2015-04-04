PLATFORM := $(shell uname -s)
VERSION := $(shell git describe --tags HEAD --always)
RELEASE = /etc/redhat-release
MAKE = make

ifeq ($(PLATFORM),Darwin)
	DISTRO=Darwin
	BUILD_DIR=darwin
else ifeq ($(PLATFORM),FreeBSD)
	DISTRO=FreeBSD
	BUILD_DIR=freebsd
	MAKE=gmake
else ifneq ("$(wildcard $(RELEASE))","")
	# Red Hat-based distro
	DISTRO := $(shell rpm -qf /etc/redhat-release | sed 's/-.*//g')
	VERSION := $(shell grep -o "release [6-7]" $(RELEASE) | sed 's/release //g')
	BUILD_DIR=$(DISTRO)$(VERSION)
else
	RELEASE=/etc/lsb-release
	DISTRO := $(shell if [ -f "$(RELEASE)" ]; then echo "Ubuntu"; fi)
	ifeq ($(DISTRO),Ubuntu)
		BUILD_DIR := $(shell lsb_release -sc)
	else
		DISTRO=Unknown
	endif
endif

DEFINES := CTEST_OUTPUT_ON_FAILURE=1

all: .setup
	cd build/$(BUILD_DIR) && cmake ../.. && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

debug: .setup
	cd build/$(BUILD_DIR) && DEBUG=True cmake ../../ && \
	  $(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

test_debug: .setup
	cd build/$(BUILD_DIR) && DEBUG=True cmake ../../ && \
		$(DEFINES) $(MAKE) test --no-print-directory $(MAKEFLAGS)

analyze: .setup
	cd build/$(BUILD_DIR) && ANALYZE=True cmake ../../ && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

sanitize: .setup
	cd build/$(BUILD_DIR) && SANITIZE=True cmake ../../ && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

sdk: .setup
	cd build/$(BUILD_DIR) && SDK=True cmake ../../ && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

test_sdk: .setup
	cd build/$(BUILD_DIR) && SDK=True cmake ../../ && \
		$(DEFINES) $(MAKE) test --no-print-directory $(MAKEFLAGS)

debug_sdk: .setup
	cd build/$(BUILD_DIR) && SDK=True DEBUG=True cmake ../../ && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

test_debug_sdk: .setup
	cd build/$(BUILD_DIR) && SDK=True DEBUG=True cmake ../../ && \
		$(DEFINES) $(MAKE) test --no-print-directory $(MAKEFLAGS)

deps: .setup
	./tools/provision.sh build build/$(BUILD_DIR)

distclean:
	rm -rf .sources build/$(BUILD_DIR) doxygen/html doxygen/latex
ifeq ($(PLATFORM),Linux)
		rm -rf build/linux
endif

.setup:
ifeq ($(DISTRO),Unknown)
	@echo Unknown, non-Redhat, non-Ubuntu based Linux distro
	false
endif
	mkdir -p build/$(BUILD_DIR)
ifeq ($(PLATFORM),Linux)
		ln -snf $(BUILD_DIR) build/linux
endif

package:
	# Alias for packages (do not use CPack)
	cd build/$(BUILD_DIR) && cmake ../../ && \
		$(DEFINES) $(MAKE) packages --no-print-directory $(MAKEFLAGS)

%::
	cd build/$(BUILD_DIR) && cmake ../.. && \
		$(DEFINES) $(MAKE) --no-print-directory $@
