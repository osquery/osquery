# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(smartmontoolsMain)
  if(NOT DEFINED PLATFORM_LINUX AND NOT DEFINED PLATFORM_MACOS)
    return()
  endif()

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_smartmontools
    "${library_root}/atacmds.cpp"
    "${library_root}/atacmdnames.cpp"
    "${library_root}/ataidentify.cpp"
    "${library_root}/ataprint.cpp"
    "${library_root}/dev_ata_cmd_set.cpp"
    "${library_root}/libsmartctl.cpp"
    "${library_root}/smartctl_common.cpp"
    "${library_root}/libsmartctl_ata.cpp"
    "${library_root}/ata_common.cpp"
    "${library_root}/dev_intelliprop.cpp"
    "${library_root}/dev_interface.cpp"
    "${library_root}/knowndrives.cpp"
    "${library_root}/scsicmds.cpp"
    "${library_root}/scsiata.cpp"
    "${library_root}/scsiprint.cpp"
    "${library_root}/utility.cpp"
  )
  set(public_include_file_list
    libsmartctl.h
    smartctl_errs.h
  )

  foreach(public_include_file ${public_include_file_list})
    configure_file(
      "${library_root}/${public_include_file}"
      "${CMAKE_CURRENT_BINARY_DIR}/smartmontools/${public_include_file}"
      COPYONLY
    )
  endforeach()

  if(DEFINED PLATFORM_LINUX)
    target_sources(thirdparty_smartmontools PRIVATE
      "${library_root}/dev_areca.cpp"
      "${library_root}/cciss.cpp"
      "${library_root}/os_linux.cpp"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_sources(thirdparty_smartmontools PRIVATE
      "${library_root}/os_darwin.cpp"
    )
  endif()

  set(BUILD_INFO_DEFINITION "BUILD_INFO=\"(local build)\"")

  target_compile_definitions(thirdparty_smartmontools PRIVATE
    HAVE_CONFIG_H
    ${BUILD_INFO_DEFINITION}
    SMARTMONTOOLS_SYSCONFDIR=\"/usr/local/etc\"
    SMARTMONTOOLS_SMARTDSCRIPTDIR=\"/usr/local/etc\"
    SMARTMONTOOLS_DRIVEDBDIR=\"/usr/local/share/smartmontools\"
  )

  target_compile_definitions(thirdparty_smartmontools PUBLIC
    HAVE_STRTOULL
  )

  target_link_libraries(thirdparty_smartmontools PRIVATE
    thirdparty_cxx_settings
  )

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_smartmontools PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/linux"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_smartmontools PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/macos"
    )
  endif()

  target_include_directories(thirdparty_smartmontools PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}"
    "${library_root}"
  )

  target_include_directories(thirdparty_smartmontools SYSTEM INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}"
    "${library_root}"
  )
endfunction()

smartmontoolsMain()
