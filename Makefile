PLATFORM := $(shell uname -s)
VERSION := $(shell git describe --tags HEAD --always)
MAKE = make

SHELL := /bin/bash

DISTRO := $(shell . ./tools/lib.sh; _platform)
DISTRO_VERSION := $(shell . ./tools/lib.sh; _distro $(DISTRO))
ifeq ($(DISTRO),darwin)
	BUILD_DIR = darwin
else
	BUILD_DIR = $(DISTRO_VERSION)
endif

DEFINES := CTEST_OUTPUT_ON_FAILURE=1
.PHONY: docs

all: .setup
	cd build/$(BUILD_DIR) && cmake ../.. && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

docs: .setup
	cd build && cmake .. && \
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

deps: .setup
	./tools/provision.sh build build/$(BUILD_DIR)

distclean:
	rm -rf .sources build/$(BUILD_DIR) build/debug_$(BUILD_DIR) build/docs
ifeq ($(PLATFORM),Linux)
		rm -rf build/linux
endif

.setup:
ifeq ($(DISTRO),unknown_version)
	@echo Unknown, non-Redhat, non-Ubuntu based Linux distro
	false
endif
	@mkdir -p build/$(BUILD_DIR)
	@mkdir -p build/debug_$(BUILD_DIR)
ifeq ($(PLATFORM),Linux)
		@ln -snf $(BUILD_DIR) build/linux
		@ln -snf debug_$(BUILD_DIR) build/debug_linux
endif

package:
	# Alias for packages (do not use CPack)
	cd build/$(BUILD_DIR) && cmake ../../ && \
		$(DEFINES) $(MAKE) packages --no-print-directory $(MAKEFLAGS)

%::
	cd build/$(BUILD_DIR) && cmake ../.. && \
		$(DEFINES) $(MAKE) --no-print-directory $@
