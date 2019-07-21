# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(utillinuxMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_util-linux
    "${library_root}/libblkid/src/getsize.c"
    "${library_root}/libblkid/src/dev.c"
    "${library_root}/libblkid/src/devname.c"
    "${library_root}/libblkid/src/config.c"
    "${library_root}/libblkid/src/superblocks/exfat.c"
    "${library_root}/libblkid/src/superblocks/superblocks.c"
    "${library_root}/libblkid/src/superblocks/zfs.c"
    "${library_root}/libblkid/src/superblocks/romfs.c"
    "${library_root}/libblkid/src/superblocks/ocfs.c"
    "${library_root}/libblkid/src/superblocks/vfat.c"
    "${library_root}/libblkid/src/superblocks/jmicron_raid.c"
    "${library_root}/libblkid/src/superblocks/hpfs.c"
    "${library_root}/libblkid/src/superblocks/nilfs.c"
    "${library_root}/libblkid/src/superblocks/netware.c"
    "${library_root}/libblkid/src/superblocks/f2fs.c"
    "${library_root}/libblkid/src/superblocks/ext.c"
    "${library_root}/libblkid/src/superblocks/squashfs.c"
    "${library_root}/libblkid/src/superblocks/xfs.c"
    "${library_root}/libblkid/src/superblocks/ufs.c"
    "${library_root}/libblkid/src/superblocks/ddf_raid.c"
    "${library_root}/libblkid/src/superblocks/reiserfs.c"
    "${library_root}/libblkid/src/superblocks/drbdproxy_datalog.c"
    "${library_root}/libblkid/src/superblocks/adaptec_raid.c"
    "${library_root}/libblkid/src/superblocks/cramfs.c"
    "${library_root}/libblkid/src/superblocks/isw_raid.c"
    "${library_root}/libblkid/src/superblocks/linux_raid.c"
    "${library_root}/libblkid/src/superblocks/nvidia_raid.c"
    "${library_root}/libblkid/src/superblocks/highpoint_raid.c"
    "${library_root}/libblkid/src/superblocks/btrfs.c"
    "${library_root}/libblkid/src/superblocks/luks.c"
    "${library_root}/libblkid/src/superblocks/refs.c"
    "${library_root}/libblkid/src/superblocks/swap.c"
    "${library_root}/libblkid/src/superblocks/iso9660.c"
    "${library_root}/libblkid/src/superblocks/lvm.c"
    "${library_root}/libblkid/src/superblocks/udf.c"
    "${library_root}/libblkid/src/superblocks/minix.c"
    "${library_root}/libblkid/src/superblocks/ntfs.c"
    "${library_root}/libblkid/src/superblocks/vxfs.c"
    "${library_root}/libblkid/src/superblocks/hfs.c"
    "${library_root}/libblkid/src/superblocks/ubifs.c"
    "${library_root}/libblkid/src/superblocks/jfs.c"
    "${library_root}/libblkid/src/superblocks/lsi_raid.c"
    "${library_root}/libblkid/src/superblocks/drbdmanage.c"
    "${library_root}/libblkid/src/superblocks/sysv.c"
    "${library_root}/libblkid/src/superblocks/drbd.c"
    "${library_root}/libblkid/src/superblocks/via_raid.c"
    "${library_root}/libblkid/src/superblocks/befs.c"
    "${library_root}/libblkid/src/superblocks/bcache.c"
    "${library_root}/libblkid/src/superblocks/vmfs.c"
    "${library_root}/libblkid/src/superblocks/silicon_raid.c"
    "${library_root}/libblkid/src/superblocks/bfs.c"
    "${library_root}/libblkid/src/superblocks/gfs.c"
    "${library_root}/libblkid/src/superblocks/promise_raid.c"
    "${library_root}/libblkid/src/encode.c"
    "${library_root}/libblkid/src/verify.c"
    "${library_root}/libblkid/src/devno.c"
    "${library_root}/libblkid/src/cache.c"
    "${library_root}/libblkid/src/probe.c"
    "${library_root}/libblkid/src/llseek.c"
    "${library_root}/libblkid/src/tag.c"
    "${library_root}/libblkid/src/init.c"
    "${library_root}/libblkid/src/read.c"
    "${library_root}/libblkid/src/topology/md.c"
    "${library_root}/libblkid/src/topology/sysfs.c"
    "${library_root}/libblkid/src/topology/dm.c"
    "${library_root}/libblkid/src/topology/topology.c"
    "${library_root}/libblkid/src/topology/lvm.c"
    "${library_root}/libblkid/src/topology/evms.c"
    "${library_root}/libblkid/src/topology/ioctl.c"
    "${library_root}/libblkid/src/resolve.c"
    "${library_root}/libblkid/src/save.c"
    "${library_root}/libblkid/src/version.c"
    "${library_root}/libblkid/src/partitions/aix.c"
    "${library_root}/libblkid/src/partitions/solaris_x86.c"
    "${library_root}/libblkid/src/partitions/unixware.c"
    "${library_root}/libblkid/src/partitions/bsd.c"
    "${library_root}/libblkid/src/partitions/gpt.c"
    "${library_root}/libblkid/src/partitions/dos.c"
    "${library_root}/libblkid/src/partitions/ultrix.c"
    "${library_root}/libblkid/src/partitions/mac.c"
    "${library_root}/libblkid/src/partitions/sgi.c"
    "${library_root}/libblkid/src/partitions/minix.c"
    "${library_root}/libblkid/src/partitions/partitions.c"
    "${library_root}/libblkid/src/partitions/sun.c"
    "${library_root}/libblkid/src/evaluate.c"

    "${library_root}/libfdisk/src/test.c"
    "${library_root}/libfdisk/src/partition.c"
    "${library_root}/libfdisk/src/utils.c"
    "${library_root}/libfdisk/src/table.c"
    "${library_root}/libfdisk/src/bsd.c"
    "${library_root}/libfdisk/src/gpt.c"
    "${library_root}/libfdisk/src/dos.c"
    "${library_root}/libfdisk/src/sgi.c"
    "${library_root}/libfdisk/src/context.c"
    "${library_root}/libfdisk/src/iter.c"
    "${library_root}/libfdisk/src/alignment.c"
    "${library_root}/libfdisk/src/init.c"
    "${library_root}/libfdisk/src/label.c"
    "${library_root}/libfdisk/src/sun.c"
    "${library_root}/libfdisk/src/version.c"
    "${library_root}/libfdisk/src/ask.c"
    "${library_root}/libfdisk/src/parttype.c"
    "${library_root}/libfdisk/src/script.c"
    
    "${library_root}/libsmartcols/src/line.c"
    "${library_root}/libsmartcols/src/test.c"
    "${library_root}/libsmartcols/src/table.c"
    "${library_root}/libsmartcols/src/table_print.c"
    "${library_root}/libsmartcols/src/iter.c"
    "${library_root}/libsmartcols/src/init.c"
    "${library_root}/libsmartcols/src/cell.c"
    "${library_root}/libsmartcols/src/symbols.c"
    "${library_root}/libsmartcols/src/column.c"
    "${library_root}/libsmartcols/src/version.c"

    "${library_root}/libuuid/src/isnull.c"
    "${library_root}/libuuid/src/copy.c"
    "${library_root}/libuuid/src/uuid_time.c"
    "${library_root}/libuuid/src/test_uuid.c"
    "${library_root}/libuuid/src/pack.c"
    "${library_root}/libuuid/src/gen_uuid.c"
    "${library_root}/libuuid/src/unpack.c"
    "${library_root}/libuuid/src/clear.c"
    "${library_root}/libuuid/src/compare.c"
    "${library_root}/libuuid/src/unparse.c"
    "${library_root}/libuuid/src/parse.c"

    "${library_root}/libmount/src/test.c"
    "${library_root}/libmount/src/optmap.c"
    "${library_root}/libmount/src/utils.c"
    "${library_root}/libmount/src/tab_diff.c"
    "${library_root}/libmount/src/context_umount.c"
    "${library_root}/libmount/src/lock.c"
    "${library_root}/libmount/src/context_mount.c"
    "${library_root}/libmount/src/cache.c"
    "${library_root}/libmount/src/tab_update.c"
    "${library_root}/libmount/src/context.c"
    "${library_root}/libmount/src/fs.c"
    "${library_root}/libmount/src/iter.c"
    "${library_root}/libmount/src/init.c"
    "${library_root}/libmount/src/tab.c"
    "${library_root}/libmount/src/tab_parse.c"
    "${library_root}/libmount/src/monitor.c"
    "${library_root}/libmount/src/version.c"
    "${library_root}/libmount/src/context_loopdev.c"
    "${library_root}/libmount/src/optstr.c"

    "${library_root}/misc-utils/findmnt.c"
    "${library_root}/misc-utils/blkid.c"
    "${library_root}/misc-utils/lsblk.c"
    "${library_root}/misc-utils/cal.c"
    "${library_root}/misc-utils/mcookie.c"
    "${library_root}/misc-utils/whereis.c"
    "${library_root}/misc-utils/logger.c"
    "${library_root}/misc-utils/rename.c"
    "${library_root}/misc-utils/findfs.c"
    "${library_root}/misc-utils/uuidd.c"
    "${library_root}/misc-utils/wipefs.c"
    "${library_root}/misc-utils/lslocks.c"
    "${library_root}/misc-utils/kill.c"
    "${library_root}/misc-utils/uuidgen.c"
    "${library_root}/misc-utils/look.c"
    "${library_root}/misc-utils/namei.c"
    "${library_root}/misc-utils/getopt.c"

    "${library_root}/lib/crc32.c"
    "${library_root}/lib/procutils.c"
    "${library_root}/lib/at.c"
    "${library_root}/lib/strv.c"
    "${library_root}/lib/sysfs.c"
    "${library_root}/lib/timeutils.c"
    "${library_root}/lib/canonicalize.c"
    "${library_root}/lib/monotonic.c"
    "${library_root}/lib/match.c"
    "${library_root}/lib/md5.c"
    "${library_root}/lib/mangle.c"
    "${library_root}/lib/crc64.c"
    "${library_root}/lib/ttyutils.c"
    "${library_root}/lib/loopdev.c"
    "${library_root}/lib/color-names.c"
    "${library_root}/lib/linux_version.c"
    "${library_root}/lib/timer.c"
    "${library_root}/lib/fileutils.c"
    "${library_root}/lib/strutils.c"
    "${library_root}/lib/path.c"
    "${library_root}/lib/blkdev.c"
    "${library_root}/lib/exec_shell.c"
    "${library_root}/lib/randutils.c"
    "${library_root}/lib/mbsalign.c"
    "${library_root}/lib/setproctitle.c"
    "${library_root}/lib/pager.c"
    "${library_root}/lib/swapprober.c"
    "${library_root}/lib/colors.c"
    "${library_root}/lib/langinfo.c"
    "${library_root}/lib/ismounted.c"
    "${library_root}/lib/env.c"
    "${library_root}/lib/cpuset.c"
  )

  target_compile_definitions(thirdparty_util-linux PRIVATE
    HAVE_CONFIG_H
    LOCALEDIR=\"/usr/share/locale\"
    _PATH_LOCALSTATEDIR=\"/run\"
  )

  target_link_libraries(thirdparty_util-linux PUBLIC
    global_c_settings
    thirdparty_silence_warnings
  )

  target_compile_options(thirdparty_util-linux PRIVATE
    -include config.h
  )

  target_include_directories(thirdparty_util-linux SYSTEM PUBLIC
    "${library_root}/libblkid/src"
    "${library_root}/libfdisk/src"
    "${library_root}/libsmartcols/src"
    "${library_root}/libuuid/src"
    "${library_root}/libmount/src"
    "${library_root}/include"
    "${library_root}"
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
  )

  # Generate the include files
  set(LIBBLKID_VERSION "2.27.0")
  set(LIBBLKID_DATE "02-Nov-2015")

  set(LIBFDISK_VERSION "2.27.0")
  set(LIBFDISK_MAJOR_VERSION 2)
  set(LIBFDISK_MINOR_VERSION 27)
  set(LIBFDISK_PATCH_VERSION 0)

  set(LIBSMARTCOLS_VERSION "2.27.0")

  set(LIBMOUNT_VERSION "2.27.0")
  set(LIBMOUNT_MAJOR_VERSION 2)
  set(LIBMOUNT_MINOR_VERSION 27)
  set(LIBMOUNT_PATCH_VERSION 0)

  set(public_header_list
    "uuid:libuuid/src/uuid.h"
    "blkid:libblkid/src/blkid.h.in"
    "fdisk:libfdisk/src/libfdisk.h.in"
    "smartcols:libsmartcols/src/libsmartcols.h.in"
    "libmount:libmount/src/libmount.h.in"
  )

  set(public_header_root "${CMAKE_CURRENT_BINARY_DIR}/include")

  foreach(public_header_info ${public_header_list})
    string(REPLACE ":" ";" public_header_info "${public_header_info}")
    list(GET public_header_info 0 include_folder_name)
    list(GET public_header_info 1 include_file_path)

    set(output_folder "${public_header_root}/${include_folder_name}")
    set(source_file "${library_root}/${include_file_path}")

    get_filename_component(include_file_name_only "${include_file_path}" NAME_WE)
    get_filename_component(include_file_name_ext "${include_file_path}" EXT)

    if("${include_file_name_ext}" STREQUAL ".h.in")
      set(configure_mode "")
    else()
      set(configure_mode "COPYONLY")
    endif()

    set(output_file "${output_folder}/${include_file_name_only}.h")
    configure_file("${source_file}" "${output_file}" ${configure_mode})

    target_include_directories(thirdparty_util-linux SYSTEM PUBLIC
      "${output_folder}"
    )
  endforeach()

  target_include_directories(thirdparty_util-linux SYSTEM PUBLIC
    "${public_header_root}"
  )
endfunction()

utillinuxMain()
