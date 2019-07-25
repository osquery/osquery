# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

# http://pkgs.fedoraproject.org/repo/pkgs/udev/udev-173.tar.bz2/91a88a359b60bbd074b024883cc0dbde/udev-173.tar.bz2

function(libudevMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_libudev
    "${library_root}/extras/accelerometer/accelerometer.c"
    "${library_root}/extras/ata_id/ata_id.c"
    "${library_root}/extras/cdrom_id/cdrom_id.c"
    "${library_root}/extras/collect/collect.c"
    "${library_root}/libudev/libudev-device-private.c"
    "${library_root}/extras/firmware/firmware.c"
    "${library_root}/extras/input_id/input_id.c"
    "${library_root}/libudev/libudev.c"
    "${library_root}/libudev/libudev-device.c"
    "${library_root}/libudev/libudev-enumerate.c"
    "${library_root}/libudev/libudev-list.c"
    "${library_root}/libudev/libudev-monitor.c"
    "${library_root}/libudev/libudev-queue.c"
    "${library_root}/libudev/libudev-util.c"
    "${library_root}/extras/path_id/path_id.c"
    "${library_root}/libudev/libudev-queue-private.c"
    "${library_root}/extras/scsi_id/scsi_id.c"
    "${library_root}/extras/scsi_id/scsi_serial.c"
    "${library_root}/udev/sd-daemon.c"
    "${library_root}/udev/udevadm.c"
    "${library_root}/udev/udevadm-control.c"
    "${library_root}/udev/udevadm-info.c"
    "${library_root}/udev/udevadm-monitor.c"
    "${library_root}/udev/udevadm-settle.c"
    "${library_root}/udev/udevadm-test.c"
    "${library_root}/udev/udevadm-trigger.c"
    "${library_root}/udev/udev-ctrl.c"
    "${library_root}/udev/udevd.c"
    "${library_root}/udev/udev-event.c"
    "${library_root}/udev/udev-node.c"
    "${library_root}/udev/udev-rules.c"
    "${library_root}/udev/udev-watch.c"
    "${library_root}/extras/usb_id/usb_id.c"
    "${library_root}/extras/v4l_id/v4l_id.c"
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

  target_link_libraries(thirdparty_libudev PUBLIC
    global_c_settings
  )

  target_link_libraries(thirdparty_libudev PRIVATE
    thirdparty_source_module_warnings
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
