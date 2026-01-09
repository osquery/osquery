# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libbpfMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/src")

  set(libbpf_sources
    "${library_root}/bpf.c"
    "${library_root}/btf.c"
    "${library_root}/btf_dump.c"
    "${library_root}/btf_iter.c"
    "${library_root}/btf_relocate.c"
    "${library_root}/elf.c"
    "${library_root}/features.c"
    "${library_root}/gen_loader.c"
    "${library_root}/hashmap.c"
    "${library_root}/libbpf.c"
    "${library_root}/libbpf_probes.c"
    "${library_root}/libbpf_utils.c"
    "${library_root}/linker.c"
    "${library_root}/netlink.c"
    "${library_root}/nlattr.c"
    "${library_root}/relo_core.c"
    "${library_root}/ringbuf.c"
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

  target_link_libraries(thirdparty_libbpf PRIVATE
    thirdparty_c_settings
    thirdparty_libelf
    thirdparty_zlib
  )

  target_include_directories(thirdparty_libbpf PRIVATE
    "${library_root}"
  )

  target_include_directories(thirdparty_libbpf SYSTEM INTERFACE
    "${library_root}"
  )

  # libbpf headers are often included as <bpf/libbpf.h>
  # We should provide an interface that supports this or 
  # manually symlink headers if needed. osquery usually 
  # prefers flattened includes or specific search paths.
  target_include_directories(thirdparty_libbpf SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include/uapi"
  )
endfunction()

libbpfMain()
