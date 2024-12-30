# Copyright (c) 2021-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(generateInstallDirectives)
  get_property(augeas_lenses_path
    GLOBAL PROPERTY "AUGEAS_LENSES_FOLDER_PATH"
  )

  if(PLATFORM_LINUX)
    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
      set(CMAKE_INSTALL_PREFIX "/opt/agenttool" CACHE PATH "" FORCE)
    endif()

    install(
      FILES "tools/deployment/linux_packaging/deb/conffiles"
      DESTINATION "/control/deb"
    )

    install(
      FILES "tools/deployment/linux_packaging/deb/agenttoold.service"
      DESTINATION "/control/deb/lib/systemd/system"
    )

    install(
      FILES "tools/deployment/linux_packaging/deb/copyright"
      DESTINATION "/control/deb"
    )

    install(
      FILES "tools/deployment/linux_packaging/deb/osquery.initd"
      DESTINATION "/control/deb/etc/init.d"
      RENAME "agenttoold"

      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ             GROUP_EXECUTE
        WORLD_READ             WORLD_EXECUTE
    )

    install(
      FILES "tools/deployment/linux_packaging/rpm/osquery.initd"
      DESTINATION "/control/rpm/etc/init.d"
      RENAME "agenttoold"

      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ             GROUP_EXECUTE
        WORLD_READ             WORLD_EXECUTE
    )

    install(
      FILES "tools/deployment/linux_packaging/rpm/agenttoold.service"
      DESTINATION "/control/rpm/lib/systemd/system"
    )

    install(
      FILES "tools/deployment/linux_packaging/postinst"
      DESTINATION "/control"
    )

    install(
      TARGETS agenttoold
      DESTINATION "bin"
    )

    execute_process(
      COMMAND "${CMAKE_COMMAND}" -E create_symlink agenttoold agenttooli
      WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    )

    install(
      FILES "${CMAKE_CURRENT_BINARY_DIR}/agenttooli"
      DESTINATION "bin"
    )

    install(
      FILES "tools/deployment/agenttoolctl"
      DESTINATION "bin"

      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ             GROUP_EXECUTE
        WORLD_READ             WORLD_EXECUTE
    )

    install(
      FILES "tools/deployment/osquery.example.conf"
      DESTINATION "share/agenttool"
    )

    install(
      DIRECTORY "${augeas_lenses_path}/"
      DESTINATION "share/agenttool/lenses"
      FILES_MATCHING PATTERN "*.aug"
      PATTERN "tests" EXCLUDE
    )

    install(
      FILES "${augeas_lenses_path}/../COPYING"
      DESTINATION "share/agenttool/lenses"
    )

    install(
      DIRECTORY "packs"
      DESTINATION "share/agenttool"
    )

    install(
      FILES "${CMAKE_SOURCE_DIR}/tools/deployment/certs.pem"
      DESTINATION "share/agenttool/certs"
    )

    install(
      FILES "tools/deployment/linux_packaging/agenttoold.sysconfig"
      DESTINATION "/control/deb/etc/default"
      RENAME "agenttoold"
    )

    install(
      FILES "tools/deployment/linux_packaging/agenttoold.sysconfig"
      DESTINATION "/control/rpm/etc/sysconfig"
      RENAME "agenttoold"
    )

    install(
      FILES "LICENSE"
      DESTINATION "/control"
      RENAME "LICENSE.txt"
    )

  elseif(PLATFORM_WINDOWS)

    # CMake doesn't prefer 'Program Files' on x64 platforms, more information
    # here: https://gitlab.kitware.com/cmake/cmake/-/issues/18312
    # This is a workaround, to ensure that we leverage 'Program Files' when
    # on a 64 bit system.
    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
      if(CMAKE_SIZEOF_VOID_P MATCHES "8")
        set(CMAKE_INSTALL_PREFIX "/Program Files/${CMAKE_PROJECT_NAME}" CACHE PATH "" FORCE)
      else()
        set(CMAKE_INSTALL_PREFIX "/Program Files (x86)/${CMAKE_PROJECT_NAME}" CACHE PATH "" FORCE)
      endif()
    endif()

    install(
      TARGETS agenttoold
      DESTINATION "agenttoold"
    )

    install(
      PROGRAMS "$<TARGET_FILE:agenttoold>"
      DESTINATION "."
      RENAME "agenttooli.exe"
    )

    install(
      DIRECTORY "tools/deployment/windows_packaging/chocolatey/tools"
      DESTINATION "/control/nupkg"
    )

    install(
      FILES "LICENSE"
      DESTINATION "/control/nupkg/extras"
      RENAME "LICENSE.txt"
    )

    install(
      FILES "LICENSE"
      DESTINATION "/control"
      RENAME "LICENSE.txt"
    )

    # Icon for the MSI package
    install(
      FILES "tools/deployment/windows_packaging/osquery.ico"
      DESTINATION "/control"
    )

    # Icon for the nuget package
    install(
      FILES "tools/deployment/windows_packaging/osquery.png"
      DESTINATION "/control"
    )

    install(
      FILES "tools/deployment/windows_packaging/chocolatey/VERIFICATION.txt"
      DESTINATION "/control/nupkg/extras"
    )

    install(
      FILES "tools/deployment/osquery.example.conf"
      DESTINATION "."
      RENAME "osquery.conf"
    )

    install(
      FILES "tools/wel/osquery.man"
      DESTINATION "."
    )

    install(
      FILES "tools/deployment/windows_packaging/manage-osqueryd.ps1"
      DESTINATION "."
    )

    install(
      FILES "tools/deployment/windows_packaging/osquery_utils.ps1"
      DESTINATION "."
    )

    install(
      FILES "tools/deployment/windows_packaging/osquery.flags"
      DESTINATION "."
    )

    install(
      FILES "tools/deployment/windows_packaging/manage-osqueryd.ps1"
      DESTINATION "/control/nupkg/extras"
    )

    install(
      FILES "tools/deployment/windows_packaging/osquery_utils.ps1"
      DESTINATION "/control/nupkg/tools"
    )

    install(
      FILES "tools/deployment/windows_packaging/msi/osquery_wix_patch.xml"
      DESTINATION "/control/msi"
    )

    install(
      FILES "tools/deployment/certs.pem"
      DESTINATION "certs"
    )

    install(
      DIRECTORY "packs"
      DESTINATION "."
    )

    install(
      DIRECTORY
      DESTINATION "log"
    )

  elseif(PLATFORM_MACOS)

    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
      set(CMAKE_INSTALL_PREFIX "/opt/agenttool" CACHE PATH "" FORCE)
    endif()

    install(
      FILES
        "tools/deployment/macos_packaging/osquery.entitlements"
        "tools/deployment/macos_packaging/embedded.provisionprofile"
        "${CMAKE_BINARY_DIR}/tools/deployment/macos_packaging/Info.plist"
        "tools/deployment/macos_packaging/PkgInfo"

      DESTINATION
        "/control"
    )

    install(
      FILES
        "tools/deployment/macos_packaging/pkg/productbuild.sh"

      DESTINATION
        "/control/pkg"

      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ             GROUP_EXECUTE
        WORLD_READ             WORLD_EXECUTE
    )

    install(
      TARGETS agenttoold
      DESTINATION "bin"
    )

    execute_process(
      COMMAND "${CMAKE_COMMAND}" -E create_symlink agenttoold agenttoold
      WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    )

    install(
      FILES "${CMAKE_CURRENT_BINARY_DIR}/agenttooli"
      DESTINATION "bin"
    )

    install(
      FILES "tools/deployment/agenttoolctl"
      DESTINATION "bin"
    )

    install(
      DIRECTORY "${augeas_lenses_path}"
      DESTINATION "/private/var/agenttool"
      FILES_MATCHING PATTERN "*.aug"
      PATTERN "tests" EXCLUDE
    )

    install(
      DIRECTORY "packs"
      DESTINATION "/private/var/agenttool"
    )

    install(
      FILES "tools/deployment/certs.pem"
      DESTINATION "/private/var/agenttool/certs"
    )

    install(
      FILES
        "tools/deployment/osquery.example.conf"

      DESTINATION
        "/private/var/agenttool"
    )

    install(
      FILES
        "tools/deployment/macos_packaging/pkg/io.osquery.agent.conf"
        "tools/deployment/macos_packaging/pkg/io.osquery.agent.plist"

      DESTINATION
        "/control/pkg"
    )

    install(
      FILES "LICENSE"
      DESTINATION "/control"
      RENAME "LICENSE.txt"
    )

    install(
      TARGETS agenttoold
      DESTINATION "osquery.app/Contents/MacOS"
      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ             GROUP_EXECUTE
        WORLD_READ             WORLD_EXECUTE 
    )

    install(
      FILES
        "tools/deployment/macos_packaging/embedded.provisionprofile"
        "${CMAKE_BINARY_DIR}/tools/deployment/macos_packaging/Info.plist"
        "tools/deployment/macos_packaging/PkgInfo"

      DESTINATION
        "osquery.app/Contents"
    )

    install(
      FILES "tools/deployment/agenttoolctl"
      DESTINATION "osquery.app/Contents/Resources"
      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ             GROUP_EXECUTE
        WORLD_READ             WORLD_EXECUTE 
    )

  else()
    message(FATAL_ERROR "Unsupported platform")
  endif()
endfunction()
