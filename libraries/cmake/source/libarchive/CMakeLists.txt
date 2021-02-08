# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libarchiveMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  set(library_srcs
    "${library_root}/libarchive/archive_acl.c"
    "${library_root}/libarchive/archive_check_magic.c"
    "${library_root}/libarchive/archive_cryptor.c"
    "${library_root}/libarchive/archive_digest.c"
    "${library_root}/libarchive/archive_entry.c"
    "${library_root}/libarchive/archive_entry_sparse.c"
    "${library_root}/libarchive/archive_entry_xattr.c"
    "${library_root}/libarchive/archive_hmac.c"
    "${library_root}/libarchive/archive_ppmd7.c"
    "${library_root}/libarchive/archive_random.c"
    "${library_root}/libarchive/archive_rb.c"
    "${library_root}/libarchive/archive_string.c"
    "${library_root}/libarchive/archive_string_sprintf.c"
    "${library_root}/libarchive/archive_util.c"
    "${library_root}/libarchive/archive_version_details.c"
    "${library_root}/libarchive/archive_virtual.c"
    "${library_root}/libarchive/archive_write.c"
    "${library_root}/libarchive/archive_write_open_fd.c"
    "${library_root}/libarchive/archive_write_open_filename.c"
    "${library_root}/libarchive/archive_write_set_format_7zip.c"
    "${library_root}/libarchive/archive_write_set_format.c"
    "${library_root}/libarchive/archive_write_set_format_cpio.c"
    "${library_root}/libarchive/archive_write_set_format_cpio_newc.c"
    "${library_root}/libarchive/archive_write_set_format_gnutar.c"
    "${library_root}/libarchive/archive_write_set_format_iso9660.c"
    "${library_root}/libarchive/archive_write_set_format_mtree.c"
    "${library_root}/libarchive/archive_write_set_format_pax.c"
    "${library_root}/libarchive/archive_write_set_format_raw.c"
    "${library_root}/libarchive/archive_write_set_format_shar.c"
    "${library_root}/libarchive/archive_write_set_format_ustar.c"
    "${library_root}/libarchive/archive_write_set_format_warc.c"
    "${library_root}/libarchive/archive_write_set_format_xar.c"
    "${library_root}/libarchive/archive_write_set_format_zip.c"
    "${library_root}/libarchive/archive_write_set_passphrase.c"
  )

  if(DEFINED PLATFORM_WINDOWS)
    list(APPEND library_srcs
      "${library_root}/libarchive/archive_entry_copy_bhfi.c"
      "${library_root}/libarchive/archive_windows.c"
      "${library_root}/libarchive/archive_write_disk_windows.c"
      "${library_root}/libarchive/filter_fork_windows.c"
    )
  endif()

  add_library(thirdparty_libarchive ${library_srcs})

  target_compile_definitions(thirdparty_libarchive PRIVATE
    HAVE_CONFIG_H
    archive_EXPORTS
    LIBARCHIVE_STATIC
    LIST_H
  )

  target_link_libraries(thirdparty_libarchive PUBLIC
    thirdparty_openssl
    thirdparty_zlib
    thirdparty_bzip2
    thirdparty_lzma
    thirdparty_libxml2
  )

  target_link_libraries(thirdparty_libarchive PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_libarchive PRIVATE
    "${library_root}/src"
    "${library_root}/libarchive_fe"
    "${library_root}/libarchive"
  )

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_libarchive PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_libarchive PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos"
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    target_include_directories(thirdparty_libarchive PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/windows"
    )
  endif()

  target_include_directories(thirdparty_libarchive SYSTEM INTERFACE
    "${library_root}/libarchive"
  )
endfunction()

libarchiveMain()
