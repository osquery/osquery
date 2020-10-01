# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(sleuthkitMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_sleuthkit INTERFACE)

  add_library(thirdparty_sleuthkit_cpp
    "${library_root}/tsk/auto/auto.cpp"
    "${library_root}/tsk/auto/auto_db.cpp"
    "${library_root}/tsk/auto/case_db.cpp"
    "${library_root}/tsk/auto/guid.cpp"
    "${library_root}/tsk/auto/is_image_supported.cpp"
    "${library_root}/tsk/auto/tsk_db.cpp"
    "${library_root}/tsk/base/tsk_error_win32.cpp"
    "${library_root}/tsk/fs/fatfs_dent.cpp"
    "${library_root}/tsk/fs/ntfs_dent.cpp"
    "${library_root}/tsk/fs/walk_cpp.cpp"
    "${library_root}/tsk/fs/yaffs.cpp"
    "${library_root}/tsk/hashdb/binsrch_index.cpp"
    "${library_root}/tsk/img/img_writer.cpp"
  )

  add_library(thirdparty_sleuthkit_c
    "${library_root}/tsk/base/XGetopt.c"
    "${library_root}/tsk/base/crc.c"
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
    "${library_root}/tsk/fs/dcalc_lib.c"
    "${library_root}/tsk/fs/dcat_lib.c"
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
    "${library_root}/tsk/fs/usn_journal.c"
    "${library_root}/tsk/fs/usnjls_lib.c"
    "${library_root}/tsk/hashdb/encase.c"
    "${library_root}/tsk/hashdb/hashkeeper.c"
    "${library_root}/tsk/hashdb/hdb_base.c"
    "${library_root}/tsk/hashdb/idxonly.c"
    "${library_root}/tsk/hashdb/md5sum.c"
    "${library_root}/tsk/hashdb/nsrl.c"
    "${library_root}/tsk/hashdb/tsk_hashdb.c"
    "${library_root}/tsk/img/aff.c"
    "${library_root}/tsk/img/ewf.c"
    "${library_root}/tsk/img/img_io.c"
    "${library_root}/tsk/img/img_open.c"
    "${library_root}/tsk/img/img_types.c"
    "${library_root}/tsk/img/mult_files.c"
    "${library_root}/tsk/img/raw.c"
    "${library_root}/tsk/img/vhd.c"
    "${library_root}/tsk/img/vmdk.c"
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

  target_compile_definitions(thirdparty_sleuthkit_c PRIVATE
    HAVE_CONFIG_H
    _THREAD_SAFE
  )

  target_compile_definitions(thirdparty_sleuthkit_cpp PRIVATE
    HAVE_CONFIG_H
    _THREAD_SAFE
  )

  if(DEFINED PLATFORM_POSIX)
    target_compile_options(thirdparty_sleuthkit_c PRIVATE
      -pthread
    )

    target_compile_options(thirdparty_sleuthkit_cpp PRIVATE
      -pthread
    )
  endif()

  target_link_libraries(thirdparty_sleuthkit_c PUBLIC
    thirdparty_zlib
  )

  target_link_libraries(thirdparty_sleuthkit_c PRIVATE
    thirdparty_c_settings
  )

  target_link_libraries(thirdparty_sleuthkit_cpp PRIVATE
    thirdparty_cxx_settings
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_include_directories(thirdparty_sleuthkit_c PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/windows/tsk"
      "${CMAKE_CURRENT_SOURCE_DIR}/config/windows"
    )

    target_include_directories(thirdparty_sleuthkit_cpp PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/windows/tsk"
      "${CMAKE_CURRENT_SOURCE_DIR}/config/windows"
    )
  elseif(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_sleuthkit_c PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux/tsk"
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux"
    )

    target_include_directories(thirdparty_sleuthkit_cpp PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux/tsk"
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_sleuthkit_c PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos/tsk"
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos"
    )

    target_include_directories(thirdparty_sleuthkit_cpp PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos/tsk"
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos"
    )
  endif()

  target_include_directories(thirdparty_sleuthkit_c PRIVATE
    "${library_root}"
  )

  target_include_directories(thirdparty_sleuthkit_cpp PRIVATE
    "${library_root}"
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_include_directories(thirdparty_sleuthkit SYSTEM INTERFACE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/windows"
    )
  elseif(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_sleuthkit SYSTEM INTERFACE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_sleuthkit SYSTEM INTERFACE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos"
    )
  endif()

  target_include_directories(thirdparty_sleuthkit SYSTEM INTERFACE
    "${library_root}"
  )

  target_link_libraries(thirdparty_sleuthkit INTERFACE
    thirdparty_sleuthkit_c
    thirdparty_sleuthkit_cpp
  )
endfunction()

sleuthkitMain()
