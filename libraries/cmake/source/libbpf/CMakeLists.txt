# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libbpfMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/src")

  # Create a bpf/ include shim directory so headers can be included as <bpf/libbpf.h>
  set(bpf_shim_dir "${CMAKE_CURRENT_BINARY_DIR}/include_shim")
  file(MAKE_DIRECTORY "${bpf_shim_dir}")
  
  # Create symlink: include_shim/bpf -> src/src (where libbpf.h lives)
  set(bpf_symlink "${bpf_shim_dir}/bpf")
  if(NOT EXISTS "${bpf_symlink}")
    file(CREATE_LINK "${library_root}" "${bpf_symlink}" SYMBOLIC)
  endif()

  set(libbpf_sources
    "${library_root}/bpf.c"
    "${library_root}/bpf_prog_linfo.c"
    "${library_root}/btf.c"
    "${library_root}/btf_dump.c"
    "${library_root}/btf_iter.c"
    "${library_root}/btf_relocate.c"
    "${library_root}/elf.c"
    "${library_root}/features.c"
    "${library_root}/gen_loader.c"
    "${library_root}/hashmap.c"
    "${library_root}/libbpf.c"
    "${library_root}/libbpf_errno.c"
    "${library_root}/libbpf_probes.c"
    "${library_root}/linker.c"
    "${library_root}/netlink.c"
    "${library_root}/nlattr.c"
    "${library_root}/relo_core.c"
    "${library_root}/ringbuf.c"
    "${library_root}/str_error.c"
    "${library_root}/strset.c"
    "${library_root}/usdt.c"
    "${library_root}/zip.c"
  )

  add_library(thirdparty_libbpf
    ${libbpf_sources}
  )

  target_compile_definitions(thirdparty_libbpf PRIVATE
    PIC
    _GNU_SOURCE
    __LIBBPF_STRERRNO_MAX=4096
  )

  target_compile_options(thirdparty_libbpf PRIVATE
    -include "${CMAKE_CURRENT_SOURCE_DIR}/include/pt_regs_fix.h"
  )

  target_link_libraries(thirdparty_libbpf PRIVATE
    thirdparty_c_settings
    thirdparty_libelf
    thirdparty_zlib
  )

  target_include_directories(thirdparty_libbpf PRIVATE
    "${library_root}"
    "${OSQUERY_TOOLCHAIN_SYSROOT}/usr/include"
  )

  # These are internal libbpf headers needed only for compilation
  target_include_directories(thirdparty_libbpf PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include/uapi"
  )

  target_include_directories(thirdparty_libbpf SYSTEM INTERFACE
    "${library_root}"
  )

  target_include_directories(thirdparty_libbpf SYSTEM INTERFACE
    "${bpf_shim_dir}"
  )

endfunction()

libbpfMain()
