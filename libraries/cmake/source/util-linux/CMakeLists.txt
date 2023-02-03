# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

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
    "${library_root}/libblkid/src/superblocks/apfs.c"
    "${library_root}/libblkid/src/superblocks/bitlocker.c"
    "${library_root}/libblkid/src/superblocks/bluestore.c"
    "${library_root}/libblkid/src/superblocks/exfs.c"
    "${library_root}/libblkid/src/superblocks/mpool.c"
    "${library_root}/libblkid/src/superblocks/stratis.c"
    "${library_root}/libblkid/src/superblocks/ubi.c"
    "${library_root}/libblkid/src/superblocks/vdo.c"
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
    "${library_root}/libblkid/src/partitions/atari.c"
    "${library_root}/libblkid/src/evaluate.c"

    "${library_root}/libuuid/src/isnull.c"
    "${library_root}/libuuid/src/copy.c"
    "${library_root}/libuuid/src/uuid_time.c"
    "${library_root}/libuuid/src/pack.c"
    "${library_root}/libuuid/src/gen_uuid.c"
    "${library_root}/libuuid/src/unpack.c"
    "${library_root}/libuuid/src/clear.c"
    "${library_root}/libuuid/src/compare.c"
    "${library_root}/libuuid/src/unparse.c"
    "${library_root}/libuuid/src/parse.c"
    "${library_root}/libuuid/src/predefined.c"

    "${library_root}/lib/crc32.c"
    "${library_root}/lib/crc32c.c"
    "${library_root}/lib/procutils.c"
    "${library_root}/lib/strv.c"
    "${library_root}/lib/sysfs.c"
    "${library_root}/lib/timeutils.c"
    "${library_root}/lib/canonicalize.c"
    "${library_root}/lib/monotonic.c"
    "${library_root}/lib/match.c"
    "${library_root}/lib/md5.c"
    "${library_root}/lib/mangle.c"
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
    "${library_root}/lib/ismounted.c"
    "${library_root}/lib/env.c"
    "${library_root}/lib/cpuset.c"
    "${library_root}/lib/pty-session.c"
    "${library_root}/lib/idcache.c"
    "${library_root}/lib/mbsedit.c"
    "${library_root}/lib/pwdutils.c"
    "${library_root}/lib/sha1.c"
    "${library_root}/lib/signames.c"
    "${library_root}/lib/caputils.c"
    "${library_root}/lib/plymouth-ctrl.c"
  )

  # Rename crc32c function name to ul_crc32c to prevent collisions,
  # as it is done by the library itself with crc32 -> ul_crc32
  set_source_files_properties(
    "${library_root}/lib/crc32c.c"
    "${library_root}/libblkid/src/superblocks/mpool.c"
    "${library_root}/libblkid/src/superblocks/stratis.c"
    PROPERTIES COMPILE_FLAGS -Dcrc32c=ul_crc32c
  )

  target_compile_definitions(thirdparty_util-linux PRIVATE
    HAVE_CONFIG_H
    LOCALEDIR=\"/usr/share/locale\"
    _PATH_LOCALSTATEDIR=\"/run\"
  )

  target_link_libraries(thirdparty_util-linux PRIVATE
    thirdparty_c_settings
  )

  target_compile_options(thirdparty_util-linux PRIVATE
    -include config.h
  )

  target_include_directories(thirdparty_util-linux PRIVATE
    "${library_root}/libblkid/src"
    "${library_root}/libuuid/src"
    "${library_root}/include"
    "${library_root}"
    "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/${TARGET_PROCESSOR}/include/blkid"
  )

  # This file needs a prefix different from the rest, so we move it into the build folder,
  # creating the needed prefix.
  configure_file("${library_root}/libuuid/src/uuid.h" "${CMAKE_CURRENT_BINARY_DIR}/include/uuid/uuid.h" @ONLY)

  target_include_directories(thirdparty_util-linux SYSTEM PUBLIC
    "${CMAKE_CURRENT_BINARY_DIR}/include"
    "${library_root}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/${TARGET_PROCESSOR}/include"
  )
endfunction()

utillinuxMain()
