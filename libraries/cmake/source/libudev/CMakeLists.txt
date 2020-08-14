# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

# http://pkgs.fedoraproject.org/repo/pkgs/udev/udev-173.tar.bz2/91a88a359b60bbd074b024883cc0dbde/udev-173.tar.bz2

function(libudevMain)
  set(library_root "${OSQUERY_libudev_ROOT_DIR}")

  add_library(thirdparty_libudev
    "${library_root}/libudev/libudev-device-private.c"
    "${library_root}/libudev/libudev.c"
    "${library_root}/libudev/libudev-device.c"
    "${library_root}/libudev/libudev-enumerate.c"
    "${library_root}/libudev/libudev-list.c"
    "${library_root}/libudev/libudev-monitor.c"
    "${library_root}/libudev/libudev-queue.c"
    "${library_root}/libudev/libudev-util.c"
    "${library_root}/libudev/libudev-queue-private.c"
  )

  target_compile_definitions(thirdparty_libudev PRIVATE
    "FIRMWARE_PATH=\"/lib/firmware/updates/\", \"/lib/firmware/\""
    HAVE_CONFIG_H
    LIBEXECDIR=\"/lib/udev\"
    SYSCONFDIR=\"/etc\"
  )

  target_compile_options(thirdparty_libudev PRIVATE
    -include config.h
  )

  target_link_libraries(thirdparty_libudev PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_libudev PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
    "${library_root}/libudev"
  )

  target_include_directories(thirdparty_libudev SYSTEM INTERFACE
    "${library_root}/libudev"
  )
endfunction()

libudevMain()
