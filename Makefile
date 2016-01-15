PLATFORM := $(shell uname -s)
GIT_EXISTS := $(shell which git)
BASH_EXISTS := $(shell which bash)
VERSION := $(shell git describe --tags HEAD --always)
SHELL := $(shell which bash)

MAKE = make
ifeq ($(PLATFORM),FreeBSD)
	MAKE = gmake
endif

DISTRO := $(shell . ./tools/lib.sh; _platform)
DISTRO_VERSION := $(shell . ./tools/lib.sh; _distro $(DISTRO))
ifeq ($(DISTRO),darwin)
	ifeq ($(DISTRO_VERSION), 10.11)
		BUILD_DIR = darwin
	else
		BUILD_DIR = darwin$(DISTRO_VERSION)
	endif
else ifeq ($(DISTRO),freebsd)
	BUILD_DIR = freebsd$(DISTRO_VERSION)
else
	BUILD_DIR = $(DISTRO_VERSION)
endif

DEFINES := CTEST_OUTPUT_ON_FAILURE=1
.PHONY: docs build

all: .setup
	cd build/$(BUILD_DIR) && cmake ../../ && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

docs: .setup
	cd build && cmake ../ && \
		$(DEFINES) $(MAKE) docs --no-print-directory $(MAKEFLAGS)

debug: .setup
	cd build/debug_$(BUILD_DIR) && DEBUG=True cmake ../../ && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

test_debug: .setup
	cd build/debug_$(BUILD_DIR) && DEBUG=True cmake ../../ && \
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
	cd build/debug_$(BUILD_DIR) && SDK=True DEBUG=True cmake ../../ && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

test_debug_sdk: .setup
	cd build/debug_$(BUILD_DIR) && SDK=True DEBUG=True cmake ../../ && \
		$(DEFINES) $(MAKE) test --no-print-directory $(MAKEFLAGS)

build:
	cd build/$(BUILD_DIR) && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

debug_build:
	cd build/debug_$(BUILD_DIR) && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

test_build:
	cd build/$(BUILD_DIR) && \
		$(DEFINES) $(MAKE) test --no-print-directory $(MAKEFLAGS)

test_debug_build:
	cd build/debug_$(BUILD_DIR) && \
		$(DEFINES) $(MAKE) test --no-print-directory $(MAKEFLAGS)

deps: .setup
	./tools/provision.sh build build/$(BUILD_DIR)

clean: .setup
	cd build/$(BUILD_DIR) && cmake ../../ && \
		$(DEFINES) $(MAKE) clean --no-print-directory $(MAKEFLAGS)

distclean:
	rm -rf .sources build/$(BUILD_DIR) build/debug_$(BUILD_DIR) build/docs
ifeq ($(PLATFORM),Linux)
		rm -rf build/linux
endif

.setup:
ifeq ($(GIT_EXISTS),)
	@echo "Problem: cannot find 'git'"
	false
endif
ifeq ($(BASH_EXISTS),)
	@echo "Problem: cannot find 'bash'"
	false
endif

ifeq ($(DISTRO),unknown_version)
	@echo Unknown, non-Redhat, non-Ubuntu based Linux distro
	false
endif
	@mkdir -p build/docs
	@mkdir -p build/$(BUILD_DIR)
	@mkdir -p build/debug_$(BUILD_DIR)
ifeq ($(PLATFORM),Linux)
	@ln -snf $(BUILD_DIR) build/linux
	@ln -snf debug_$(BUILD_DIR) build/debug_linux
endif

package: .setup
	# Alias for packages (do not use CPack)
	cd build/$(BUILD_DIR) && PACKAGE=True cmake ../../ && \
		$(DEFINES) $(MAKE) packages --no-print-directory $(MAKEFLAGS)

packages: .setup
	cd build/$(BUILD_DIR) && PACKAGE=True cmake ../../ && \
		$(DEFINES) $(MAKE) packages --no-print-directory $(MAKEFLAGS)

sync: .setup
	cd build/$(BUILD_DIR) && PACKAGE=True cmake ../../ && \
		$(DEFINES) $(MAKE) sync --no-print-directory $(MAKEFLAGS)

%::
	cd build/$(BUILD_DIR) && cmake ../../ && \
		$(DEFINES) $(MAKE) --no-print-directory $@
