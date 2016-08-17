PLATFORM := $(shell uname -s)
BASH_EXISTS := $(shell which bash)
SHELL := $(shell which bash)

ifneq ($(MAKECMDGOALS),deps)
GIT_EXISTS := $(shell which git)
endif

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

ifneq ($(OSQUERY_DEPS),)
	DEPS_DIR = $(OSQUERY_DEPS)
else
	DEPS_DIR = /usr/local/osquery
endif
PATH_SET := PATH="$(DEPS_DIR)/bin:/usr/local/bin:$(PATH)"
CMAKE := $(PATH_SET) CXXFLAGS="-L$(DEPS_DIR)/lib" cmake ../../
DOCS_CMAKE := $(PATH_SET) CXXFLAGS="-L$(DEPS_DIR)/lib" cmake ../
FORMAT_COMMAND := python tools/formatting/git-clang-format.py "--commit" "master" "-f"

DEFINES := CTEST_OUTPUT_ON_FAILURE=1
.PHONY: docs build

all: .setup
	@cd build/$(BUILD_DIR) && $(CMAKE) && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

docs: .setup
	@cd build && DOCS=True $(DOCS_CMAKE) && \
		$(DEFINES) $(MAKE) docs --no-print-directory $(MAKEFLAGS)

format_master:
	@echo "[+] clang-format (`which clang-format`) version: `clang-format --version`"
	@$(PATH_SET) $(FORMAT_COMMAND)

debug: .setup
	@cd build/debug_$(BUILD_DIR) && DEBUG=True $(CMAKE) && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

test_debug: .setup
	@cd build/debug_$(BUILD_DIR) && DEBUG=True $(CMAKE) && \
		$(DEFINES) $(MAKE) test --no-print-directory $(MAKEFLAGS)

analyze: .setup
	@cd build/$(BUILD_DIR) && ANALYZE=True $(CMAKE) && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

sanitize: .setup
	@cd build/$(BUILD_DIR) && SANITIZE=True $(CMAKE) && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

sdk: .setup
	@cd build/$(BUILD_DIR) && SDK=True $(CMAKE) && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

test_sdk: .setup
	@cd build/$(BUILD_DIR) && SDK=True $(CMAKE) && \
		$(DEFINES) $(MAKE) test --no-print-directory $(MAKEFLAGS)

debug_sdk: .setup
	@cd build/debug_$(BUILD_DIR) && SDK=True DEBUG=True $(CMAKE) && \
		$(DEFINES) $(MAKE) --no-print-directory $(MAKEFLAGS)

test_debug_sdk: .setup
	@cd build/debug_$(BUILD_DIR) && SDK=True DEBUG=True $(CMAKE) && \
		$(DEFINES) $(MAKE) test --no-print-directory $(MAKEFLAGS)

check:
	@echo "[+] cppcheck (`which cppcheck`) version: `cppcheck --version`"
	@$(PATH_SET) cppcheck --quiet --enable=all --error-exitcode=0 \
		-I ./include ./osquery
	@# We want check to produce an error if there are critical issues.
	@echo ""
	@$(PATH_SET) cppcheck --quiet --enable=warning --error-exitcode=1 \
		-I ./include ./osquery

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
	./tools/provision.sh build $(BUILD_DIR)

clean: .setup
	@cd build/$(BUILD_DIR) && $(CMAKE) && \
		$(DEFINES) $(MAKE) clean --no-print-directory $(MAKEFLAGS)

strip: .setup
	cd build/$(BUILD_DIR) && find ./osquery -executable -type f | xargs strip

distclean:
	rm -rf .sources build/$(BUILD_DIR) build/debug_$(BUILD_DIR) build/docs
ifeq ($(PLATFORM),Linux)
		rm -rf build/linux
endif

depsclean:
	./tools/provision.sh clean $(BUILD_DIR)

.setup:
ifneq ($(MAKECMDGOALS),deps)
ifeq ($(GIT_EXISTS),)
	@echo "Problem: cannot find 'git'"
	@false
endif
endif
ifeq ($(BASH_EXISTS),)
	@echo "Problem: cannot find 'bash'"
	@false
endif

ifeq ($(DISTRO),unknown_version)
	@echo Unknown, non-Redhat, non-Ubuntu based Linux distro
	@false
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
	@cd build/$(BUILD_DIR) && PACKAGE=True $(CMAKE) && \
		$(DEFINES) $(MAKE) packages/fast --no-print-directory $(MAKEFLAGS)

debug_package: .setup
	@cd build/debug_$(BUILD_DIR) && DEBUG=True PACKAGE=True $(CMAKE) && \
		$(DEFINES) $(MAKE) packages --no-print-directory $(MAKEFLAGS)

packages: .setup
	@cd build/$(BUILD_DIR) && PACKAGE=True $(CMAKE) && \
		$(DEFINES) $(MAKE) packages/fast --no-print-directory $(MAKEFLAGS)

debug_packages:
	@cd build/debug_$(BUILD_DIR) && DEBUG=True PACKAGE=True $(CMAKE) && \
		$(DEFINES) $(MAKE) packages --no-print-directory $(MAKEFLAGS)

sync: .setup
	@cd build/$(BUILD_DIR) && PACKAGE=True $(CMAKE) && \
		$(DEFINES) $(MAKE) sync --no-print-directory $(MAKEFLAGS)

%::
	@cd build/$(BUILD_DIR) && $(CMAKE) && \
		$(DEFINES) $(MAKE) --no-print-directory $@
