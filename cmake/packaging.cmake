# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

set(linux_supported_packaging_systems
  DEB
  RPM
  TGZ
)

set(windows_supported_packaging_system
  WIX
  NuGet
)

set(macos_supported_packaging_system
  productbuild
  TGZ
  # Bundle
)

function(identifyPackagingSystem)
  if(NOT PACKAGING_SYSTEM)
      identifyPackagingSystemFromPlatform()
  endif()

  if(DEFINED PLATFORM_LINUX)
    if(NOT ${PACKAGING_SYSTEM} IN_LIST linux_supported_packaging_systems)
      message(WARNING "Selected an unsupported packaging system, please choose from this list: ${linux_supported_packaging_systems}")
    endif()
  elseif(DEFINED PLATFORM_WINDOWS)
    if(NOT ${PACKAGING_SYSTEM} IN_LIST windows_supported_packaging_system)
      message(WARNING "Selected an unsupported packaging system, please choose from this list: ${windows_supported_packaging_system}")
    endif()
  elseif(DEFINED PLATFORM_MACOS)
    if(NOT ${PACKAGING_SYSTEM} IN_LIST macos_supported_packaging_system)
      message(WARNING "Selected an unsupported packaging system, please choose from this list: ${macos_supported_packaging_system}")
    endif()
  endif()

  findPackagingTool()
endfunction()

function(identifyPackagingSystemFromPlatform)
  if(DEFINED PLATFORM_LINUX)
    find_program(lsb_release_exec lsb_release)

    if(NOT "${lsb_release_exec}" STREQUAL "lsb_release_exec_NOTFOUND")
      execute_process(COMMAND ${lsb_release_exec} -is
                      OUTPUT_VARIABLE lsb_release_id_short
                      OUTPUT_STRIP_TRAILING_WHITESPACE
      )
    endif()

    set(deb_distros
      Ubuntu
      Debian
    )

    set(rpm_distros
      Fedora
      CentOS
    )

    if("${lsb_release_id_short}" IN_LIST deb_distros)
      set(platform_packaging_system "DEB")
    elseif("${lsb_release_id_short}" IN_LIST rpm_distros)
      set(platform_packaging_system "RPM")
    else()
      set(platform_packaging_system "TGZ")
      message(WARNING
        "Failed to identify Linux flavor, either lsb_release is missing or we couldn't identify your distro.\n"
        "The package target will now generate TGZ, if you want to generate native packages please install lsb_release, "
        "or choose a different packaging system through the CMake variable PACKAGING_SYSTEM; available values are DEB, RPM"
      )
    endif()
  elseif(DEFINED PLATFORM_WINDOWS)
    set(platform_packaging_system "WIX")
  elseif(DEFINED PLATFORM_MACOS)
    set(platform_packaging_system "productbuild")
  endif()

  overwrite_cache_variable("PACKAGING_SYSTEM" "STRING" "${platform_packaging_system}")
endfunction()

function(findPackagingTool)
  if(PACKAGING_SYSTEM STREQUAL "DEB")
    unset(PACKAGING_TOOL_PATH_INTERNAL CACHE)
    unset(deb_packaging_tool CACHE)
    find_program(deb_packaging_tool dpkg)

    if("${deb_packaging_tool}" STREQUAL "deb_packaging_tool-NOTFOUND")
      message(WARNING "Packaging tool dpkg needed to create DEB packages has not been found, please install it if you want to create packages")
    endif()
  elseif(PACKAGING_SYSTEM STREQUAL "RPM")
    unset(PACKAGING_TOOL_PATH_INTERNAL CACHE)
    unset(rpm_packaging_tool CACHE)
    find_program(rpm_packaging_tool rpmbuild)

    if("${rpm_packaging_tool}" STREQUAL "rpm_packaging_tool-NOTFOUND")
      message(WARNING "Packaging tool rpmbuild needed to create RPM packages has not been found, please install it if you want to create packages")
    endif()
  elseif(PACKAGING_SYSTEM STREQUAL "WIX")
    find_program(candle_exec NAMES candle.exe PATHS "${WIX_ROOT_FOLDER_PATH}\\bin" "$ENV{WIX}\\bin")

    if(NOT "${candle_exec}" STREQUAL "candle_exec-NOTFOUND")
      get_filename_component(wix_root_path "${candle_exec}" DIRECTORY)
      get_filename_component(wix_root_path "${wix_root_path}" DIRECTORY)
      message(STATUS "Found WIX toolset at: ${wix_root_path}")
      set(CPACK_WIX_ROOT "${wix_root_path}")
      overwrite_cache_variable("WIX_ROOT_FOLDER_PATH" "STRING" "${wix_root_path}")
    else()
      message(WARNING
        "Could not find the WIX packaging tools, either install it or if it's already installed, please set the WIX_ROOT_FOLDER_PATH variable to the root folder of the WIX installation."
      )
    endif()
  elseif(PACKAGING_SYSTEM STREQUAL "NuGet")
    find_program(nuget_exec NAMES nuget.exe PATHS "${NUGET_ROOT_FOLDER_PATH}\\bin" "$ENV{NUGET}\\bin")

    if(NOT "${nuget_exec}" STREQUAL "nuget_exec-NOTFOUND")
      get_filename_component(nuget_root_path "${nuget_exec}" DIRECTORY)
      get_filename_component(nuget_root_path "${nuget_root_path}" DIRECTORY)
      message(STATUS "Found NuGet toolset at: ${nuget_root_path}")
      set(CPACK_NUGET_ROOT "${nuget_root_path}")
      overwrite_cache_variable("NUGET_ROOT_FOLDER_PATH" "STRING" "${nuget_root_path}")
    else()
      message(WARNING
        "Could not find the NuGet packaging tools, either install it or if it's 
        already installed, please set the NUGET_ROOT_FOLDER_PATH variable to the 
        root folder of the NuGet installation."
      )
    endif()
  endif()
endfunction()

function(generateInstallTargets)
  get_property(augeas_lenses_path GLOBAL PROPERTY AUGEAS_LENSES_FOLDER_PATH)

  if(DEFINED PLATFORM_LINUX)
    # .
    file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/linux_postinstall.sh" DESTINATION "${CMAKE_BINARY_DIR}/package/linux")
    file(RENAME "${CMAKE_BINARY_DIR}/package/linux/linux_postinstall.sh" "${CMAKE_BINARY_DIR}/package/linux/postinst")
    if("${PACKAGING_SYSTEM}" STREQUAL "DEB")
      file(WRITE "${CMAKE_BINARY_DIR}/package/linux/conffiles"
        "/etc/init.d/osqueryd\n"
        "/etc/default/osqueryd\n"
      )
    endif()

    # bin
    install(TARGETS osqueryd DESTINATION bin COMPONENT osquery)
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink osqueryd osqueryi)" COMPONENT osquery)
    install(FILES "${CMAKE_BINARY_DIR}/osqueryi" DESTINATION bin COMPONENT osquery)
    file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/osqueryctl" DESTINATION "${CMAKE_BINARY_DIR}/package/linux")
    install(PROGRAMS "${CMAKE_BINARY_DIR}/package/linux/osqueryctl" DESTINATION bin COMPONENT osquery)

    # lib
    file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/osqueryd.service" DESTINATION "${CMAKE_BINARY_DIR}/package/linux")
    if("${PACKAGING_SYSTEM}"  STREQUAL "DEB")
      # Patch the EnvironmentFile in the systemd unit
      file(READ "${CMAKE_BINARY_DIR}/package/linux/osqueryd.service" osqueryd_service_file)
      string(REPLACE "/etc/sysconfig/osqueryd" "/etc/default/osqueryd" osqueryd_service_file "${osqueryd_service_file}")
      file(WRITE "${CMAKE_BINARY_DIR}/package/linux/osqueryd.service" "${osqueryd_service_file}")
    endif()
    install(FILES "${CMAKE_BINARY_DIR}/package/linux/osqueryd.service" DESTINATION lib/systemd/system COMPONENT osquery)

    # share
    file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/osquery.example.conf" DESTINATION "${CMAKE_BINARY_DIR}/package/linux")
    install(FILES "${CMAKE_BINARY_DIR}/package/linux/osquery.example.conf" DESTINATION share/osquery COMPONENT osquery)

    install(DIRECTORY "${augeas_lenses_path}/"
            DESTINATION share/osquery/lenses
            COMPONENT osquery
            FILES_MATCHING PATTERN "*.aug"
            PATTERN "tests" EXCLUDE)
    install(FILES "${augeas_lenses_path}/../COPYING" DESTINATION share/osquery/lenses COMPONENT osquery)

    if("${PACKAGING_SYSTEM}" STREQUAL "DEB")
      file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/copyright.debian" DESTINATION "${CMAKE_BINARY_DIR}/package/deb")
      file(RENAME "${CMAKE_BINARY_DIR}/package/deb/copyright.debian" "${CMAKE_BINARY_DIR}/package/deb/copyright")
      install(FILES "${CMAKE_BINARY_DIR}/package/deb/copyright" DESTINATION share/doc/osquery COMPONENT osquery)
    endif()

    file(COPY "${CMAKE_SOURCE_DIR}/packs" DESTINATION "${CMAKE_BINARY_DIR}/package/linux")
    install(DIRECTORY "${CMAKE_BINARY_DIR}/package/linux/packs" DESTINATION share/osquery COMPONENT osquery)

    install(FILES "${CMAKE_SOURCE_DIR}/tools/deployment/certs.pem" DESTINATION share/osquery/certs COMPONENT osquery)

    # etc
    file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/osqueryd.sysconfig" DESTINATION "${CMAKE_BINARY_DIR}/package/linux")
    if("${PACKAGING_SYSTEM}"  STREQUAL "DEB")
      install(FILES "${CMAKE_BINARY_DIR}/package/linux/osqueryd.sysconfig" DESTINATION /etc/default RENAME osqueryd COMPONENT osquery)
    else()
      install(FILES "${CMAKE_BINARY_DIR}/package/linux/osqueryd.sysconfig" DESTINATION /etc/sysconfig RENAME osqueryd COMPONENT osquery)
    endif()

    file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/osqueryd.initd" DESTINATION "${CMAKE_BINARY_DIR}/package/linux")
    if("${PACKAGING_SYSTEM}"  STREQUAL "DEB")
      # Patch /etc/sysconfig to /etc/default in the initd script
      file(READ "${CMAKE_BINARY_DIR}/package/linux/osqueryd.initd" osqueryd_initd_file)
      string(REPLACE "/etc/sysconfig" "/etc/default" osqueryd_initd_file "${osqueryd_initd_file}")
      file(WRITE "${CMAKE_BINARY_DIR}/package/linux/osqueryd.initd" "${osqueryd_initd_file}")
    endif()
    install(PROGRAMS "${CMAKE_BINARY_DIR}/package/linux/osqueryd.initd" DESTINATION /etc/init.d RENAME "osqueryd" COMPONENT osquery)
    install(DIRECTORY DESTINATION /etc/osquery COMPONENT osquery)

    # var
    install(DIRECTORY DESTINATION /var/log/osquery COMPONENT osquery)
    install(DIRECTORY DESTINATION /var/osquery COMPONENT osquery)
  elseif(DEFINED PLATFORM_WINDOWS)
    # .
    install(PROGRAMS "$<TARGET_FILE:osqueryd>" DESTINATION . RENAME osqueryi.exe)

    if("${PACKAGING_SYSTEM}" STREQUAL "NuGet")
      set(win_packager "nuget")
      # Grab the Chocolatey management scripts
      file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/chocolatey/tools" DESTINATION "${CMAKE_BINARY_DIR}/package/${win_packager}")
      install(DIRECTORY "${CMAKE_BINARY_DIR}/package/${win_packager}/tools" DESTINATION .)

      # Chocolatey requires a LICENSE.txt and VERIFICATION.txt file in all 
      # packages containing .exe, .msi, or .zip files.
      file(COPY "${CMAKE_SOURCE_DIR}/LICENSE" DESTINATION "${CMAKE_BINARY_DIR}/package/${win_packager}")
      install(FILES "${CMAKE_BINARY_DIR}/package/${win_packager}/LICENSE" DESTINATION . RENAME LICENSE.txt)
      
      file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/VERIFICATION.txt" DESTINATION "${CMAKE_BINARY_DIR}/package/${win_packager}")
      install(FILES "${CMAKE_BINARY_DIR}/package/${win_packager}/VERIFICATION.txt" DESTINATION .)
    else()
      set(win_packager "wix")
    endif()
    

    file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/osquery.example.conf" DESTINATION "${CMAKE_BINARY_DIR}/package/${win_packager}")
    install(FILES "${CMAKE_BINARY_DIR}/package/${win_packager}/osquery.example.conf" DESTINATION . RENAME osquery.conf)

    file(COPY "${CMAKE_SOURCE_DIR}/tools/wel/osquery.man" DESTINATION "${CMAKE_BINARY_DIR}/package/${win_packager}")
    install(FILES "${CMAKE_BINARY_DIR}/package/${win_packager}/osquery.man" DESTINATION .)

    file(COPY "${CMAKE_SOURCE_DIR}/tools/manage-osqueryd.ps1" DESTINATION "${CMAKE_BINARY_DIR}/package/${win_packager}")
    install(FILES "${CMAKE_BINARY_DIR}/package/${win_packager}/manage-osqueryd.ps1" DESTINATION .)

    file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/chocolatey/tools/osquery_utils.ps1" DESTINATION "${CMAKE_BINARY_DIR}/package/${win_packager}")
    install(FILES "${CMAKE_BINARY_DIR}/package/${win_packager}/osquery_utils.ps1" DESTINATION .)

    file(WRITE "${CMAKE_BINARY_DIR}/package/${win_packager}/osquery.flags")
    install(FILES "${CMAKE_BINARY_DIR}/package/${win_packager}/osquery.flags" DESTINATION .)

    # osqueryd
    install(TARGETS osqueryd DESTINATION osqueryd)

    # log
    install(DIRECTORY DESTINATION log)

    # packs
    file(COPY "${CMAKE_SOURCE_DIR}/packs" DESTINATION "${CMAKE_BINARY_DIR}/package/${win_packager}")
    install(DIRECTORY "${CMAKE_BINARY_DIR}/package/${win_packager}/packs" DESTINATION .)

    # certs
    install(FILES "${CMAKE_SOURCE_DIR}/tools/deployment/certs.pem" DESTINATION certs)
  elseif(DEFINED PLATFORM_MACOS)
    # bin
    install(TARGETS osqueryd DESTINATION bin COMPONENT osquery)
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink osqueryd osqueryi)" COMPONENT osquery)
    install(FILES "${CMAKE_BINARY_DIR}/osqueryi" DESTINATION bin COMPONENT osquery)
    file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/osqueryctl" DESTINATION "${CMAKE_BINARY_DIR}/package/pkg")
    install(PROGRAMS "${CMAKE_BINARY_DIR}/package/pkg/osqueryctl" DESTINATION bin COMPONENT osquery)

    # /private/var
    install(DIRECTORY COMPONENT osquery DESTINATION /private/var/log/osquery)
    install(DIRECTORY COMPONENT osquery DESTINATION /private/var/osquery)

    install(DIRECTORY "${augeas_lenses_path}" COMPONENT osquery
            DESTINATION /private/var/osquery/lenses
            FILES_MATCHING PATTERN "*.aug"
            PATTERN "tests" EXCLUDE)

    file(COPY "${CMAKE_SOURCE_DIR}/packs" DESTINATION "${CMAKE_BINARY_DIR}/package/pkg")
    install(DIRECTORY "${CMAKE_BINARY_DIR}/package/pkg/packs" COMPONENT osquery DESTINATION /private/var/osquery)

    install(FILES "${CMAKE_SOURCE_DIR}/tools/deployment/certs.pem" COMPONENT osquery DESTINATION /private/var/osquery/certs)

    file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/com.facebook.osqueryd.conf" DESTINATION "${CMAKE_BINARY_DIR}/package/pkg")
    install(FILES "${CMAKE_BINARY_DIR}/package/pkg/com.facebook.osqueryd.conf" DESTINATION /private/var/osquery COMPONENT osquery)

    file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/com.facebook.osqueryd.plist" DESTINATION "${CMAKE_BINARY_DIR}/package/pkg")
    install(FILES "${CMAKE_BINARY_DIR}/package/pkg/com.facebook.osqueryd.plist" DESTINATION /private/var/osquery COMPONENT osquery)

    file(COPY "${CMAKE_SOURCE_DIR}/tools/deployment/osquery.example.conf" DESTINATION "${CMAKE_BINARY_DIR}/package/pkg")
    install(FILES "${CMAKE_BINARY_DIR}/package/pkg/osquery.example.conf" DESTINATION /private/var/osquery COMPONENT osquery)
  endif()

  file(COPY "${CMAKE_SOURCE_DIR}/LICENSE" DESTINATION "${CMAKE_BINARY_DIR}/package")
  file(RENAME "${CMAKE_BINARY_DIR}/package/LICENSE" "${CMAKE_BINARY_DIR}/package/LICENSE.txt")
endfunction()

macro(cleanupVersionComponent version_component output_var)
  string(REGEX MATCH "^[0-9]+" ${output_var} "${version_component}")
endmacro()

function(generatePackageTarget)

  getVersionComponents("${OSQUERY_VERSION_COMPONENTS}" "CPACK_PACKAGE_VERSION_MAJOR" "CPACK_PACKAGE_VERSION_MINOR" "CPACK_PACKAGE_VERSION_PATCH")

  if(PLATFORM_WINDOWS)
    cleanupVersionComponent("${CPACK_PACKAGE_VERSION_PATCH}" "CPACK_PACKAGE_VERSION_PATCH")
  endif()

  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "osquery is an operating system instrumentation toolchain.")
  set(CPACK_COMPONENT_OSQUERY_DESCRIPTION ${CPACK_PACKAGE_DESCRIPTION_SUMMARY})
  set(CPACK_PACKAGE_NAME "osquery")
  set(CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
  set(CPACK_PACKAGE_VENDOR "osquery")
  set(CPACK_PACKAGE_CONTACT "osquery@osquery.io")
  set(CPACK_PACKAGE_HOMEPAGE_URL "https://osquery.io")
  set(CPACK_PROJECT_CONFIG_FILE "${CMAKE_BINARY_DIR}/package/CPackConfig.cmake")
  set(CPACK_PACKAGE_RELOCATABLE ON)
  set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_BINARY_DIR}/package/LICENSE.txt")
  if(DEFINED PLATFORM_MACOS OR DEFINED PLATFORM_LINUX)
    set(CPACK_COMPONENTS_ALL osquery)
  endif()

  configure_file(cmake/CPackConfig.cmake.in package/CPackConfig.cmake @ONLY)

  set(CPACK_GENERATOR "${PACKAGING_SYSTEM}")

  # Set this on by default and off for DEB/RPM
  if(NOT CPACK_GENERATOR STREQUAL "DEB" AND NOT CPACK_GENERATOR STREQUAL "RPM")
    set(CPACK_STRIP_FILES ON)
  endif()

  if(DEFINED PLATFORM_LINUX)
    set(OSQUERY_PACKAGE_RELEASE "1.linux")
    if(CPACK_GENERATOR STREQUAL "TGZ")
      set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}_${OSQUERY_PACKAGE_RELEASE}_${TARGET_PROCESSOR}")
      set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY 0)
      set(CPACK_SET_DESTDIR ON)
    elseif(CPACK_GENERATOR STREQUAL "DEB")
      set(CPACK_DEBIAN_OSQUERY_PACKAGE_NAME ${CPACK_PACKAGE_NAME})
      set(CPACK_DEBIAN_PACKAGE_RELEASE "${OSQUERY_PACKAGE_RELEASE}")
      set(CPACK_DEBIAN_OSQUERY_FILE_NAME "DEB-DEFAULT")
      set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
      set(CPACK_DEBIAN_PACKAGE_SECTION "default")
      set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>=2.12), zlib1g")
      set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "${CPACK_PACKAGE_HOMEPAGE_URL}")
      set(CPACK_DEB_COMPONENT_INSTALL ON)
      set(CPACK_DEBIAN_DEBUGINFO_PACKAGE ON)
      set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_BINARY_DIR}/package/linux/conffiles;${CMAKE_BINARY_DIR}/package/linux/postinst")
    elseif(CPACK_GENERATOR STREQUAL "RPM")
      set(CPACK_RPM_PACKAGE_RELEASE "${OSQUERY_PACKAGE_RELEASE}")
      set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
      set(CPACK_RPM_PACKAGE_DESCRIPTION "osquery is an operating system instrumentation toolchain.")
      set(CPACK_RPM_PACKAGE_GROUP "default")
      set(CPACK_RPM_PACKAGE_LICENSE "Apache 2.0 or GPL 2.0")
      set(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.12, zlib")
      set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/package/linux/postinst")
      list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
        /etc/sysconfig
        /var
        /var/log
        /usr/lib/systemd
        /usr/lib/systemd/system
      )
      set(CPACK_RPM_DEBUGINFO_PACKAGE ON)
      set(CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX /usr/src/debug/osquery)
      set(CPACK_RPM_DEBUGINFO_FILE_NAME "RPM-DEFAULT")
    endif()
  elseif(DEFINED PLATFORM_MACOS)
    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
    set(CPACK_COMMAND_PRODUCTBUILD "${CMAKE_SOURCE_DIR}/tools/deployment/productbuild.sh")
    set(CPACK_COMMAND_PKGBUILD "${CMAKE_SOURCE_DIR}/tools/deployment/productbuild.sh")
    set(CPACK_SET_DESTDIR ON)
  elseif(DEFINED PLATFORM_WINDOWS)
    if(CPACK_GENERATOR STREQUAL "WIX")
      file(COPY "${CMAKE_SOURCE_DIR}/tools/osquery.ico" DESTINATION "${CMAKE_BINARY_DIR}/package/wix")
      file(COPY "${CMAKE_SOURCE_DIR}/cmake/wix_patches/osquery_wix_patch.xml" DESTINATION "${CMAKE_BINARY_DIR}/package/wix")
      set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
      set(CPACK_WIX_PRODUCT_ICON "${CMAKE_BINARY_DIR}/package/wix/osquery.ico")
      set(CPACK_WIX_UPGRADE_GUID "ea6c7327-461e-4033-847c-acdf2b85dede")
      set(CPACK_WIX_PATCH_FILE "${CMAKE_BINARY_DIR}/package/wix/osquery_wix_patch.xml")
      set(CPACK_PACKAGE_INSTALL_DIRECTORY "osquery")
      set(CPACK_WIX_EXTENSIONS "WixUtilExtension")
    elseif(CPACK_GENERATOR STREQUAL "NuGet")
      set(CPACK_NUGET_PACKAGE_DESCRIPTION "
        osquery allows you to easily ask questions about your Linux, macOS, and
        Windows infrastructure. Whether your goal is intrusion detection, 
        infrastructure reliability, or compliance, osquery gives you the ability
        to empower and inform a broad set of organizations within your company.
        
        ### Package Parameters
          * `/InstallService` - This creates a new windows service that will 
                                auto-start the daemon.
                                
        These parameters can be passed to the installer with the use of 
        `--params`. For example: `--params='/InstallService'`.
        "
      )
      set(OSQUERY_REPO "https://github.com/osquery/osquery/")
      set(CPACK_NUGET_PACKAGE_AUTHORS "${CPACK_PACKAGE_NAME}")
      set(CPACK_NUGET_PACKAGE_TITLE "${CPACK_PACKAGE_NAME}")
      set(CPACK_NUGET_PACKAGE_OWNERS "${CPACK_PACKAGE_NAME}")
      set(CPACK_NUGET_PACKAGE_COPYRIGHT "Copyright (c) 2014-present, The osquery authors. See LICENSE.")
      set(CPACK_NUGET_PACKAGE_LICENSEURL "${OSQUERY_REPO}blob/master/LICENSE")
      set(CPACK_NUGET_PACKAGE_ICONURL "${OSQUERY_REPO}blob/master/tools/osquery.ico")
      set(CPACK_NUGET_PACKAGE_DESCRIPTION_SUMMARY "
        osquery gives you the ability to query and log things like running 
        processes, logged in users, password changes, usb devices, firewall 
        exceptions, listening ports, and more.
        "
      )
      set(CPACK_NUGET_PACKAGE_RELEASE_NOTES "${OSQUERY_REPO}releases/tag/${CPACK_PACKAGE_VERSION}")
      set(CPACK_NUGET_PACKAGE_TAGS "infosec tools security")
    endif()
  elseif(DEFINED PLATFORM_FREEBSD)
  else()
    message(FATAL_ERROR "Unsupported platform")
  endif()

  include(CPack)

  if(DEFINED PLATFORM_MACOS OR DEFINED PLATFORM_LINUX)
    cpack_add_component(osquery REQUIRED)
  endif()
endfunction()
