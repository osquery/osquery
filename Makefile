# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

# Convenience targets for building osquery on Linux and macOS. Each target is
# a thin wrapper around tools/bootstrap-*.sh and the presets in
# CMakePresets.json, which can also be used directly (including on Windows).

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
  PRESET ?= linux
  JOBS ?= $(shell nproc)
else ifeq ($(UNAME_S),Darwin)
  PRESET ?= macos
  JOBS ?= $(shell sysctl -n hw.ncpu)
else
  $(error This Makefile supports Linux and macOS; on Windows, use the CMake presets directly)
endif

BUILD_DIR := build

.PHONY: help prerequisites configure build test clean

help:
	@echo "Targets:"
	@echo "  prerequisites  Install the build prerequisites (uses sudo)"
	@echo "  configure      Configure the build with the '$(PRESET)' CMake preset"
	@echo "  build          Build osquery (configures first if needed)"
	@echo "  test           Configure with tests enabled, build, and run the tests"
	@echo "  clean          Remove build outputs"
	@echo "Variables: PRESET=$(PRESET) JOBS=$(JOBS)"

prerequisites:
ifeq ($(UNAME_S),Linux)
	tools/bootstrap-linux.sh
else
	@echo "Automatic prerequisites are not available on macOS yet; see" \
	  "docs/wiki/development/building.md"
endif

configure:
	cmake --preset $(PRESET)

$(BUILD_DIR)/CMakeCache.txt:
	cmake --preset $(PRESET)

build: $(BUILD_DIR)/CMakeCache.txt
	cmake --build --preset $(PRESET) -j $(JOBS)

test:
	grep -q '^OSQUERY_BUILD_TESTS:BOOL=ON$$' $(BUILD_DIR)/CMakeCache.txt 2>/dev/null || \
	  cmake --preset $(PRESET) -DOSQUERY_BUILD_TESTS=ON
	cmake --build --preset $(PRESET) -j $(JOBS)
	ctest --preset $(PRESET)

clean:
	cmake --build --preset $(PRESET) --target clean
