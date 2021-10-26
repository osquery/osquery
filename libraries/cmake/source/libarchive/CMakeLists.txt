# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libarchiveMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  if(PLATFORM_LINUX)
    set(config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/linux/${TARGET_PROCESSOR}")

  elseif(PLATFORM_MACOS)
    set(config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/macos/${TARGET_PROCESSOR}")

  elseif(PLATFORM_WINDOWS)
    set(config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/windows/${TARGET_PROCESSOR}")
  endif()

  add_library(thirdparty_libarchive
    "${library_root}/libarchive/archive_acl.c"
    "${library_root}/libarchive/archive_blake2sp_ref.c"
    "${library_root}/libarchive/archive_blake2s_ref.c"
    "${library_root}/libarchive/archive_check_magic.c"
    "${library_root}/libarchive/archive_cmdline.c"
    "${library_root}/libarchive/archive_cryptor.c"
    "${library_root}/libarchive/archive_digest.c"
    "${library_root}/libarchive/archive_entry.c"
    "${library_root}/libarchive/archive_entry_copy_stat.c"
    "${library_root}/libarchive/archive_entry_link_resolver.c"
    "${library_root}/libarchive/archive_entry_sparse.c"
    "${library_root}/libarchive/archive_entry_stat.c"
    "${library_root}/libarchive/archive_entry_strmode.c"
    "${library_root}/libarchive/archive_entry_xattr.c"
    "${library_root}/libarchive/archive_getdate.c"
    "${library_root}/libarchive/archive_hmac.c"
    "${library_root}/libarchive/archive_match.c"
    "${library_root}/libarchive/archive_options.c"
    "${library_root}/libarchive/archive_pack_dev.c"
    "${library_root}/libarchive/archive_pathmatch.c"
    "${library_root}/libarchive/archive_ppmd7.c"
    "${library_root}/libarchive/archive_ppmd8.c"
    "${library_root}/libarchive/archive_random.c"
    "${library_root}/libarchive/archive_rb.c"
    "${library_root}/libarchive/archive_read_add_passphrase.c"
    "${library_root}/libarchive/archive_read_append_filter.c"
    "${library_root}/libarchive/archive_read.c"
    "${library_root}/libarchive/archive_read_data_into_fd.c"
    "${library_root}/libarchive/archive_read_disk_entry_from_file.c"
    "${library_root}/libarchive/archive_read_disk_posix.c"
    "${library_root}/libarchive/archive_read_disk_set_standard_lookup.c"
    "${library_root}/libarchive/archive_read_extract2.c"
    "${library_root}/libarchive/archive_read_extract.c"
    "${library_root}/libarchive/archive_read_open_fd.c"
    "${library_root}/libarchive/archive_read_open_file.c"
    "${library_root}/libarchive/archive_read_open_filename.c"
    "${library_root}/libarchive/archive_read_open_memory.c"
    "${library_root}/libarchive/archive_read_set_format.c"
    "${library_root}/libarchive/archive_read_set_options.c"
    "${library_root}/libarchive/archive_read_support_filter_all.c"
    "${library_root}/libarchive/archive_read_support_filter_bzip2.c"
    "${library_root}/libarchive/archive_read_support_filter_compress.c"
    "${library_root}/libarchive/archive_read_support_filter_grzip.c"
    "${library_root}/libarchive/archive_read_support_filter_gzip.c"
    "${library_root}/libarchive/archive_read_support_filter_lrzip.c"
    "${library_root}/libarchive/archive_read_support_filter_lz4.c"
    "${library_root}/libarchive/archive_read_support_filter_lzop.c"
    "${library_root}/libarchive/archive_read_support_filter_none.c"
    "${library_root}/libarchive/archive_read_support_filter_program.c"
    "${library_root}/libarchive/archive_read_support_filter_rpm.c"
    "${library_root}/libarchive/archive_read_support_filter_uu.c"
    "${library_root}/libarchive/archive_read_support_filter_xz.c"
    "${library_root}/libarchive/archive_read_support_filter_zstd.c"
    "${library_root}/libarchive/archive_read_support_format_7zip.c"
    "${library_root}/libarchive/archive_read_support_format_all.c"
    "${library_root}/libarchive/archive_read_support_format_ar.c"
    "${library_root}/libarchive/archive_read_support_format_by_code.c"
    "${library_root}/libarchive/archive_read_support_format_cab.c"
    "${library_root}/libarchive/archive_read_support_format_cpio.c"
    "${library_root}/libarchive/archive_read_support_format_empty.c"
    "${library_root}/libarchive/archive_read_support_format_iso9660.c"
    "${library_root}/libarchive/archive_read_support_format_lha.c"
    "${library_root}/libarchive/archive_read_support_format_mtree.c"
    "${library_root}/libarchive/archive_read_support_format_rar5.c"
    "${library_root}/libarchive/archive_read_support_format_rar.c"
    "${library_root}/libarchive/archive_read_support_format_raw.c"
    "${library_root}/libarchive/archive_read_support_format_tar.c"
    "${library_root}/libarchive/archive_read_support_format_warc.c"
    "${library_root}/libarchive/archive_read_support_format_xar.c"
    "${library_root}/libarchive/archive_read_support_format_zip.c"
    "${library_root}/libarchive/archive_string.c"
    "${library_root}/libarchive/archive_string_sprintf.c"
    "${library_root}/libarchive/archive_util.c"
    "${library_root}/libarchive/archive_version_details.c"
    "${library_root}/libarchive/archive_virtual.c"
    "${library_root}/libarchive/archive_write_add_filter_b64encode.c"
    "${library_root}/libarchive/archive_write_add_filter_by_name.c"
    "${library_root}/libarchive/archive_write_add_filter_bzip2.c"
    "${library_root}/libarchive/archive_write_add_filter.c"
    "${library_root}/libarchive/archive_write_add_filter_compress.c"
    "${library_root}/libarchive/archive_write_add_filter_grzip.c"
    "${library_root}/libarchive/archive_write_add_filter_gzip.c"
    "${library_root}/libarchive/archive_write_add_filter_lrzip.c"
    "${library_root}/libarchive/archive_write_add_filter_lz4.c"
    "${library_root}/libarchive/archive_write_add_filter_lzop.c"
    "${library_root}/libarchive/archive_write_add_filter_none.c"
    "${library_root}/libarchive/archive_write_add_filter_program.c"
    "${library_root}/libarchive/archive_write_add_filter_uuencode.c"
    "${library_root}/libarchive/archive_write_add_filter_xz.c"
    "${library_root}/libarchive/archive_write_add_filter_zstd.c"
    "${library_root}/libarchive/archive_write.c"
    "${library_root}/libarchive/archive_write_disk_posix.c"
    "${library_root}/libarchive/archive_write_disk_set_standard_lookup.c"
    "${library_root}/libarchive/archive_write_open_fd.c"
    "${library_root}/libarchive/archive_write_open_file.c"
    "${library_root}/libarchive/archive_write_open_filename.c"
    "${library_root}/libarchive/archive_write_open_memory.c"
    "${library_root}/libarchive/archive_write_set_format_7zip.c"
    "${library_root}/libarchive/archive_write_set_format_ar.c"
    "${library_root}/libarchive/archive_write_set_format_by_name.c"
    "${library_root}/libarchive/archive_write_set_format.c"
    "${library_root}/libarchive/archive_write_set_format_cpio_binary.c"
    "${library_root}/libarchive/archive_write_set_format_cpio.c"
    "${library_root}/libarchive/archive_write_set_format_cpio_newc.c"
    "${library_root}/libarchive/archive_write_set_format_cpio_odc.c"
    "${library_root}/libarchive/archive_write_set_format_filter_by_ext.c"
    "${library_root}/libarchive/archive_write_set_format_gnutar.c"
    "${library_root}/libarchive/archive_write_set_format_iso9660.c"
    "${library_root}/libarchive/archive_write_set_format_mtree.c"
    "${library_root}/libarchive/archive_write_set_format_pax.c"
    "${library_root}/libarchive/archive_write_set_format_raw.c"
    "${library_root}/libarchive/archive_write_set_format_shar.c"
    "${library_root}/libarchive/archive_write_set_format_ustar.c"
    "${library_root}/libarchive/archive_write_set_format_v7tar.c"
    "${library_root}/libarchive/archive_write_set_format_warc.c"
    "${library_root}/libarchive/archive_write_set_format_xar.c"
    "${library_root}/libarchive/archive_write_set_format_zip.c"
    "${library_root}/libarchive/archive_write_set_options.c"
    "${library_root}/libarchive/archive_write_set_passphrase.c"
    "${library_root}/libarchive/filter_fork_posix.c"
    "${library_root}/libarchive/xxhash.c"
  )

  if(PLATFORM_WINDOWS)
    target_sources(thirdparty_libarchive PRIVATE
      "${library_root}/libarchive/archive_entry_copy_bhfi.c"
      "${library_root}/libarchive/archive_read_disk_windows.c"
      "${library_root}/libarchive/archive_windows.c"
      "${library_root}/libarchive/archive_write_disk_windows.c"
      "${library_root}/libarchive/filter_fork_windows.c"
    )
  endif()

  target_include_directories(thirdparty_libarchive PRIVATE
    "${library_root}/libarchive"
    "${config_path}"
  )

  target_include_directories(thirdparty_libarchive SYSTEM INTERFACE
    "${library_root}/libarchive"
  )

  target_compile_definitions(thirdparty_libarchive PRIVATE
    LIBARCHIVE_STATIC
    USE_BZIP2_STATIC
    LIBXML_STATIC
    HAVE_CONFIG_H
  )

  if(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_libarchive PRIVATE
      _CRT_SECURE_NO_DEPRECATE
    )
  endif()

  target_link_libraries(thirdparty_libarchive
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_openssl
      thirdparty_zlib
      thirdparty_bzip2
      thirdparty_lzma
      thirdparty_libxml2
      thirdparty_zstd
  )
endfunction()

libarchiveMain()
