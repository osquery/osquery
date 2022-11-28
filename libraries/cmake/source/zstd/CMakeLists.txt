# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(zstdMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/lib")

  add_library(thirdparty_zstd
    "${library_root}/common/entropy_common.c"
    "${library_root}/common/fse_decompress.c"
    "${library_root}/common/threading.c"
    "${library_root}/common/pool.c"
    "${library_root}/common/zstd_common.c"
    "${library_root}/common/error_private.c"
    "${library_root}/compress/hist.c"
    "${library_root}/compress/fse_compress.c"
    "${library_root}/compress/huf_compress.c"
    "${library_root}/compress/zstd_compress.c"
    "${library_root}/compress/zstdmt_compress.c"
    "${library_root}/compress/zstd_fast.c"
    "${library_root}/compress/zstd_double_fast.c"
    "${library_root}/compress/zstd_lazy.c"
    "${library_root}/compress/zstd_opt.c"
    "${library_root}/compress/zstd_ldm.c"
    "${library_root}/decompress/huf_decompress.c"
    "${library_root}/decompress/zstd_decompress.c"
    "${library_root}/decompress/zstd_decompress_block.c"
    "${library_root}/decompress/zstd_ddict.c"
    "${library_root}/dictBuilder/cover.c"
    "${library_root}/dictBuilder/fastcover.c"
    "${library_root}/dictBuilder/divsufsort.c"
    "${library_root}/dictBuilder/zdict.c"
    "${library_root}/deprecated/zbuff_common.c"
    "${library_root}/deprecated/zbuff_compress.c"
    "${library_root}/deprecated/zbuff_decompress.c"
  )

  # We were previously not passing ZSTD_LEGACY_SUPPORT; by default, in the
  # original build system, this is set to 0.
  #
  # The logic from zstd_legacy.h handles it like this:
  #
  #    if !defined (ZSTD_LEGACY_SUPPORT) || (ZSTD_LEGACY_SUPPORT == 0)
  #      undef ZSTD_LEGACY_SUPPORT
  #      define ZSTD_LEGACY_SUPPORT 8
  #    endif
  #
  # It is then safe to add this back here and set it to zero since it
  # does not change the current behavior.
  target_compile_definitions(thirdparty_zstd PRIVATE
    ZSTD_MULTITHREAD
    ZSTD_LEGACY_SUPPORT=0
    XXH_NAMESPACE=ZSTD_
    XXH_PRIVATE_API
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_zstd PRIVATE
      ZSTD_HEAPMODE=0
      _CRT_SECURE_NO_WARNINGS
    )
  endif()

  target_link_libraries(thirdparty_zstd PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_zstd PRIVATE
    "${library_root}"
    "${library_root}/common"
  )

  target_include_directories(thirdparty_zstd SYSTEM INTERFACE
    "${library_root}"
    "${library_root}/common"
  )
endfunction()

zstdMain()
