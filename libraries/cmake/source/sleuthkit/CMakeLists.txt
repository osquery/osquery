# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(sleuthkitMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  if(DEFINED PLATFORM_POSIX)
    find_package(Threads REQUIRED)
  endif()

  if(DEFINED PLATFORM_LINUX)
    set(sleuthkit_config_path
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux/${TARGET_PROCESSOR}"
    )

  elseif(DEFINED PLATFORM_MACOS)
    set(sleuthkit_config_path
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos/${TARGET_PROCESSOR}"
    )
  endif()

  add_library(thirdparty_sleuthkit_settings INTERFACE)
  target_include_directories(thirdparty_sleuthkit_settings INTERFACE
    "${sleuthkit_config_path}"
    "${library_root}/tsk"
    "${library_root}"
  )

  if(NOT PLATFORM_WINDOWS)
    list(APPEND thirdparty_sleuthkit_settings
      HAVE_CONFIG_H
    )
  endif()

  if(PLATFORM_MACOS)
    list(APPEND sleuthkit_compile_definitions
      _THREAD_SAFE
    )

  elseif(PLATFORM_WINDOWS)
    list(APPEND sleuthkit_compile_definitions
      NOMINMAX
      _CRT_SECURE_NO_DEPRECATE
      GUID_WINDOWS
      _CRT_SECURE_NO_WARNINGS
      HAVE_LIBZ
      WIN32
      _LIB
      WINVER=0x0501
    )

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
      list(APPEND sleuthkit_compile_definitions
        DEBUG
      )

    else()
      list(APPEND sleuthkit_compile_definitions
        NDEBUG
      )
    endif()
  endif()

  target_compile_definitions(thirdparty_sleuthkit_settings INTERFACE
    ${sleuthkit_compile_definitions}
  )

  # base library
  add_library(thirdparty_sleuthkit_base_cpp OBJECT
    "${library_root}/tsk/base/tsk_error_win32.cpp"
  )

  target_link_libraries(thirdparty_sleuthkit_base_cpp PRIVATE
    thirdparty_sleuthkit_settings
    thirdparty_cxx_settings
  )

  add_library(thirdparty_sleuthkit_base
    "${library_root}/tsk/base/XGetopt.c"
    "${library_root}/tsk/base/md5c.c"
    "${library_root}/tsk/base/mymalloc.c"
    "${library_root}/tsk/base/sha1c.c"
    "${library_root}/tsk/base/tsk_endian.c"
    "${library_root}/tsk/base/tsk_error.c"
    "${library_root}/tsk/base/tsk_list.c"
    "${library_root}/tsk/base/tsk_lock.c"
    "${library_root}/tsk/base/tsk_parse.c"
    "${library_root}/tsk/base/tsk_printf.c"
    "${library_root}/tsk/base/tsk_stack.c"
    "${library_root}/tsk/base/tsk_unicode.c"
    "${library_root}/tsk/base/tsk_version.c"
  )

  if(NOT PLATFORM_WINDOWS)
    target_sources(thirdparty_sleuthkit_base PRIVATE
      "${library_root}/tsk/base/crc.c"
    )
  endif()

  target_link_libraries(thirdparty_sleuthkit_base
    PRIVATE
      thirdparty_sleuthkit_settings
      thirdparty_c_settings
      thirdparty_sleuthkit_base_cpp
  )

  # hashdb library
  add_library(thirdparty_sleuthkit_hashdb_cpp OBJECT
    "${library_root}/tsk/hashdb/binsrch_index.cpp"
    "${library_root}/tsk/hashdb/sqlite_hdb.cpp"
  )

  target_link_libraries(thirdparty_sleuthkit_hashdb_cpp PRIVATE
    thirdparty_sleuthkit_settings
    thirdparty_cxx_settings
  )

  add_library(thirdparty_sleuthkit_hashdb
    "${library_root}/tsk/hashdb/encase.c"
    "${library_root}/tsk/hashdb/hashkeeper.c"
    "${library_root}/tsk/hashdb/hdb_base.c"
    "${library_root}/tsk/hashdb/idxonly.c"
    "${library_root}/tsk/hashdb/md5sum.c"
    "${library_root}/tsk/hashdb/nsrl.c"
    "${library_root}/tsk/hashdb/tsk_hashdb.c"
  )

  target_link_libraries(thirdparty_sleuthkit_hashdb
    PRIVATE
      thirdparty_sleuthkit_settings
      thirdparty_c_settings
      thirdparty_sleuthkit_hashdb_cpp

    PUBLIC
      thirdparty_sqlite
      thirdparty_sleuthkit_base
  )

  # img library
  add_library(thirdparty_sleuthkit_img_cpp OBJECT
    "${library_root}/tsk/img/ewf.cpp"
    "${library_root}/tsk/img/img_open.cpp"
    "${library_root}/tsk/img/img_writer.cpp"
  )

  target_link_libraries(thirdparty_sleuthkit_img_cpp PRIVATE
    thirdparty_sleuthkit_settings
    thirdparty_cxx_settings
  )

  add_library(thirdparty_sleuthkit_img
    "${library_root}/tsk/img/aff.c"
    "${library_root}/tsk/img/img_io.c"
    "${library_root}/tsk/img/img_types.c"
    "${library_root}/tsk/img/mult_files.c"
    "${library_root}/tsk/img/raw.c"
    "${library_root}/tsk/img/unsupported_types.c"
    "${library_root}/tsk/img/vhd.c"
    "${library_root}/tsk/img/vmdk.c"
  )

  target_link_libraries(thirdparty_sleuthkit_img
    PRIVATE
      thirdparty_sleuthkit_settings
      thirdparty_c_settings
      thirdparty_sleuthkit_img_cpp

    PUBLIC
      thirdparty_sleuthkit_base
  )

  # util library
  add_library(thirdparty_sleuthkit_util_cpp OBJECT
    "${library_root}/tsk/util/crypto.cpp"
  )

  target_link_libraries(thirdparty_sleuthkit_util_cpp PRIVATE
    thirdparty_sleuthkit_settings
    thirdparty_cxx_settings
  )

  add_library(thirdparty_sleuthkit_util
    "${library_root}/tsk/util/detect_encryption.c"
  )

  target_link_libraries(thirdparty_sleuthkit_util
    PRIVATE
      thirdparty_sleuthkit_settings
      thirdparty_c_settings
      thirdparty_sleuthkit_util_cpp

    PUBLIC
      thirdparty_sleuthkit_img
  )

  # vs library
  add_library(thirdparty_sleuthkit_vs
    "${library_root}/tsk/vs/bsd.c"
    "${library_root}/tsk/vs/dos.c"
    "${library_root}/tsk/vs/gpt.c"
    "${library_root}/tsk/vs/mac.c"
    "${library_root}/tsk/vs/mm_io.c"
    "${library_root}/tsk/vs/mm_open.c"
    "${library_root}/tsk/vs/mm_part.c"
    "${library_root}/tsk/vs/mm_types.c"
    "${library_root}/tsk/vs/sun.c"
  )

  target_link_libraries(thirdparty_sleuthkit_vs
    PRIVATE
      thirdparty_sleuthkit_settings
      thirdparty_c_settings

    PUBLIC
      thirdparty_sleuthkit_base
      thirdparty_sleuthkit_img
      thirdparty_sleuthkit_util
  )

  # pool library
  add_library(thirdparty_sleuthkit_pool
    "${library_root}/tsk/pool/apfs_pool_compat.cpp"
    "${library_root}/tsk/pool/apfs_pool.cpp"
    "${library_root}/tsk/pool/pool_open.cpp"
    "${library_root}/tsk/pool/pool_read.cpp"
    "${library_root}/tsk/pool/pool_types.cpp"
  )

  target_link_libraries(thirdparty_sleuthkit_pool
    PRIVATE
      thirdparty_sleuthkit_settings
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_sleuthkit_base
      thirdparty_sleuthkit_fs
      thirdparty_sleuthkit_img
  )

  # auto library
  add_library(thirdparty_sleuthkit_auto
    "${library_root}/tsk/auto/auto.cpp"
    "${library_root}/tsk/auto/auto_db.cpp"
    "${library_root}/tsk/auto/case_db.cpp"
    "${library_root}/tsk/auto/db_sqlite.cpp"
    "${library_root}/tsk/auto/guid.cpp"
    "${library_root}/tsk/auto/is_image_supported.cpp"
    "${library_root}/tsk/auto/tsk_db.cpp"
  )

  target_link_libraries(thirdparty_sleuthkit_auto
    PRIVATE
      thirdparty_sleuthkit_settings
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_sleuthkit_pool
      thirdparty_sleuthkit_hashdb
  )

  # fs library
  add_library(thirdparty_sleuthkit_fs_cpp
    "${library_root}/tsk/fs/apfs_compat.cpp"
    "${library_root}/tsk/fs/apfs.cpp"
    "${library_root}/tsk/fs/apfs_fs.cpp"
    "${library_root}/tsk/fs/apfs_open.cpp"
    "${library_root}/tsk/fs/fatfs_dent.cpp"
    "${library_root}/tsk/fs/ntfs_dent.cpp"
    "${library_root}/tsk/fs/walk_cpp.cpp"
    "${library_root}/tsk/fs/yaffs.cpp"
  )

  target_link_libraries(thirdparty_sleuthkit_fs_cpp PRIVATE
    thirdparty_sleuthkit_settings
    thirdparty_cxx_settings
    thirdparty_sleuthkit_auto
  )

  add_library(thirdparty_sleuthkit_fs
    "${library_root}/tsk/fs/dcalc_lib.c"
    "${library_root}/tsk/fs/dcat_lib.c"
    "${library_root}/tsk/fs/decmpfs.c"
    "${library_root}/tsk/fs/dls_lib.c"
    "${library_root}/tsk/fs/dstat_lib.c"
    "${library_root}/tsk/fs/exfatfs.c"
    "${library_root}/tsk/fs/exfatfs_dent.c"
    "${library_root}/tsk/fs/exfatfs_meta.c"
    "${library_root}/tsk/fs/ext2fs.c"
    "${library_root}/tsk/fs/ext2fs_dent.c"
    "${library_root}/tsk/fs/ext2fs_journal.c"
    "${library_root}/tsk/fs/fatfs.c"
    "${library_root}/tsk/fs/fatfs_meta.c"
    "${library_root}/tsk/fs/fatfs_utils.c"
    "${library_root}/tsk/fs/fatxxfs.c"
    "${library_root}/tsk/fs/fatxxfs_dent.c"
    "${library_root}/tsk/fs/fatxxfs_meta.c"
    "${library_root}/tsk/fs/ffind_lib.c"
    "${library_root}/tsk/fs/ffs.c"
    "${library_root}/tsk/fs/ffs_dent.c"
    "${library_root}/tsk/fs/fls_lib.c"
    "${library_root}/tsk/fs/fs_attr.c"
    "${library_root}/tsk/fs/fs_attrlist.c"
    "${library_root}/tsk/fs/fs_block.c"
    "${library_root}/tsk/fs/fs_dir.c"
    "${library_root}/tsk/fs/fs_file.c"
    "${library_root}/tsk/fs/fs_inode.c"
    "${library_root}/tsk/fs/fs_io.c"
    "${library_root}/tsk/fs/fs_load.c"
    "${library_root}/tsk/fs/fs_name.c"
    "${library_root}/tsk/fs/fs_open.c"
    "${library_root}/tsk/fs/fs_parse.c"
    "${library_root}/tsk/fs/fs_types.c"
    "${library_root}/tsk/fs/hfs.c"
    "${library_root}/tsk/fs/hfs_dent.c"
    "${library_root}/tsk/fs/hfs_journal.c"
    "${library_root}/tsk/fs/hfs_unicompare.c"
    "${library_root}/tsk/fs/icat_lib.c"
    "${library_root}/tsk/fs/ifind_lib.c"
    "${library_root}/tsk/fs/ils_lib.c"
    "${library_root}/tsk/fs/iso9660.c"
    "${library_root}/tsk/fs/iso9660_dent.c"
    "${library_root}/tsk/fs/lzvn.c"
    "${library_root}/tsk/fs/nofs_misc.c"
    "${library_root}/tsk/fs/ntfs.c"
    "${library_root}/tsk/fs/rawfs.c"
    "${library_root}/tsk/fs/swapfs.c"
    "${library_root}/tsk/fs/unix_misc.c"
  )

  if(NOT PLATFORM_WINDOWS)
    target_sources(thirdparty_sleuthkit_fs PRIVATE
      "${library_root}/tsk/fs/usn_journal.c"
      "${library_root}/tsk/fs/usnjls_lib.c"
    )
  endif()

  target_link_libraries(thirdparty_sleuthkit_fs
    PRIVATE
      thirdparty_sleuthkit_settings
      thirdparty_c_settings
      thirdparty_sleuthkit_fs_cpp

    PUBLIC
      thirdparty_sleuthkit_base
      thirdparty_sleuthkit_vs
      thirdparty_sleuthkit_pool
      thirdparty_zlib
  )

  add_library(thirdparty_sleuthkit INTERFACE)
  target_link_libraries(thirdparty_sleuthkit INTERFACE
    thirdparty_sleuthkit_base
    thirdparty_sleuthkit_hashdb
    thirdparty_sleuthkit_img
    thirdparty_sleuthkit_util
    thirdparty_sleuthkit_vs
    thirdparty_sleuthkit_pool
    thirdparty_sleuthkit_auto
    thirdparty_sleuthkit_fs
  )

  target_include_directories(thirdparty_sleuthkit SYSTEM INTERFACE
    "${library_root}"
    "${sleuthkit_config_path}"
  )
endfunction()

sleuthkitMain()
