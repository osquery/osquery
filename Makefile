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

SYNC_DIR=build/sync

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

debug_sdk: .setup
	cd build/$(BUILD_DIR)/sdk && SDK=True DEBUG=True cmake ../../../ && \
	  $(MAKE) --no-print-directory $(MAKEFLAGS)

test_debug_sdk: .setup
	cd build/$(BUILD_DIR)/sdk && SDK=True DEBUG=True cmake ../../../ && \
	  $(MAKE) test --no-print-directory $(MAKEFLAGS)

deps: .setup
	./tools/provision.sh build build/$(BUILD_DIR)

distclean:
	rm -rf .sources build/$(BUILD_DIR) doxygen/html doxygen/latex $(SYNC_DIR)
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

sync:
	mkdir -p $(SYNC_DIR)
	rm -rf $(SYNC_DIR)/osquery*
	@
	@# merge the headers with the implementation files
	cp -R osquery $(SYNC_DIR)
	cp -R include/osquery $(SYNC_DIR)
	cp -R build/$(BUILD_DIR)/sdk/generated/ $(SYNC_DIR)/osquery
	cp osquery.thrift $(SYNC_DIR)/osquery/extensions
	@
	@# delete all of the old CMake files
	find $(SYNC_DIR) -type f -name "CMakeLists.txt" -exec rm -f {} \;
	@
	@# make the targets file
	mkdir -p $(SYNC_DIR)/code-analysis
	cd $(SYNC_DIR)/code-analysis && SDK=True cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../../../
	SDK=True
	python tools/codegen/gentargets.py -i $(SYNC_DIR)/code-analysis/compile_commands.json > $(SYNC_DIR)/osquery/TARGETS
	@
	@# wrap it up in a tarball
	cd $(SYNC_DIR) && tar -zcf osquery-sync.tar.gz osquery
	@echo "The output file is located at $(SYNC_DIR)/osquery-sync.tar.gz"

%::
	cd build/$(BUILD_DIR) && cmake ../.. && $(MAKE) --no-print-directory $@
