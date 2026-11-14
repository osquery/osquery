# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

include("${CMAKE_CURRENT_LIST_DIR}/utils.cmake")

# The osquery-toolchain v1.0 shipped with a broken LLVM installation, so
# we can't use find_package
if(OSQUERY_TOOLCHAIN_SYSROOT)
  set(llvm_bpfcodegen_hints
    HINTS "${OSQUERY_TOOLCHAIN_SYSROOT}/usr/lib"
  )
endif()

find_library(llvm_bpfcodegen_lib
  NAMES
    "libLLVMBPFCodeGen.a"

  ${llvm_bpfcodegen_hints}
)

if("${llvm_bpfcodegen_lib}" STREQUAL "llvm_bpfcodegen_lib-NOTFOUND")
  message(WARNING "The installed LLVM libraries do not support BPF")
  set(OSQUERY_BUILD_BPF false CACHE BOOL "Whether to enable and build BPF support. Useful for ossfuzz (forced OFF)" FORCE)

else()
  importSourceSubmodule(
    NAME "ebpfpub"
    SUBMODULES "src"
  )
endif()
