# make package
if(APPLE)
  add_custom_target(
    packages
    COMMAND "${CMAKE_SOURCE_DIR}/tools/deployment/make_osx_package.sh"
    COMMAND "${CMAKE_SOURCE_DIR}/tools/codegen/genapi.py" "${CMAKE_SOURCE_DIR}"
      "--output" "--directory" "${CMAKE_BINARY_DIR}"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Building default OS X package (no custom config)" VERBATIM
    DEPENDS daemon shell
  )
elseif(LINUX)
  if(DEBIAN_BASED)
    # Set basic catch-alls for debian-based systems.
    set(PACKAGE_TYPE "deb")
    set(PACKAGE_ITERATION "1.debian")
    set(PACKAGE_DEPENDENCIES
      "zlib1g"
      "libbz2-1.0"
      "libreadline6"
    )

    # Improve catch-alls for debian or ubuntu.
    if(OSQUERY_BUILD_PLATFORM STREQUAL "ubuntu")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
      )
    elseif(OSQUERY_BUILD_PLATFORM STREQUAL "debian")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
      )
    endif()

    # Ubuntu versions 2015+ will require libgcrypt20.
    # Ubuntu versions 2014+ will require libudev1.
    # Debian versions 8+ will require libgcrypt20 and libudev1.

    # Improve package and iterations for each specific distribution.
    if(NOT OSQUERY_BUILD_DISTRO STREQUAL "lucid")
      set(PACKAGE_ITERATION "1.ubuntu10")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libc6 (>=2.13)"
        "libapt-pkg4.12"
      )
    endif()

    if(OSQUERY_BUILD_DISTRO STREQUAL "precise")
      set(PACKAGE_ITERATION "1.ubuntu12")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libstdc++6"
        "libgcrypt11"
        "libudev0"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "wheezy")
      set(PACKAGE_ITERATION "1.debian7")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libstdc++6"
        "libgcrypt11"
        "libudev0"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "trusty")
      set(PACKAGE_ITERATION "1.ubuntu14")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libstdc++6 (>= 4.8)"
        "libgcrypt11"
        "libudev1"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "jessie")
      set(PACKAGE_ITERATION "1.debian8")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libstdc++6 (>= 4.8)"
        "libgcrypt20"
        "libudev1"
      )
    endif()
  elseif(REDHAT_BASED)
    set(PACKAGE_TYPE "rpm")
    set(PACKAGE_ITERATION "1.el")
    set(PACKAGE_DEPENDENCIES
      "glibc >= 2.12"
      "openssl >= 1.0"
      "bzip2-libs"
      "readline"
      "zlib"
      "rpm-libs"
    )
    if(OSQUERY_BUILD_DISTRO STREQUAL "centos6")
      set(PACKAGE_ITERATION "1.el6")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libudev"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "rhel6")
      set(PACKAGE_ITERATION "1.rhel6")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libudev"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "scientific6")
      set(PACKAGE_ITERATION "1.el6")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libudev"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "oracle6")
      set(PACKAGE_ITERATION "1.oel6")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libudev"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "centos7")
      set(PACKAGE_ITERATION "1.el7")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "rhel7")
      set(PACKAGE_ITERATION "1.rhel7")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "scientific7")
      set(PACKAGE_ITERATION "1.el7")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "oracle7")
      set(PACKAGE_ITERATION "1.oel7")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "amazon2015.03")
      set(PACKAGE_ITERATION "1.amazon2015")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
      )
    endif()
  endif()
  JOIN("${PACKAGE_DEPENDENCIES}" ", " PACKAGE_DEPENDENCIES)

  add_custom_target(
    packages
    COMMAND "${CMAKE_SOURCE_DIR}/tools/deployment/make_linux_package.sh"
      -t ${PACKAGE_TYPE} -i "${PACKAGE_ITERATION}"
      -d "${PACKAGE_DEPENDENCIES}"
    COMMAND "${CMAKE_SOURCE_DIR}/tools/codegen/genapi.py" "${CMAKE_SOURCE_DIR}"
      "--output" "--directory" "${CMAKE_BINARY_DIR}"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Building linux packages (no custom config)" VERBATIM
    DEPENDS daemon shell
  )
endif()

# Add dependencies and additional package data based on optional components.

if(NOT ${KERNEL_BINARY} STREQUAL "" AND
    EXISTS "${CMAKE_BINARY_DIR}/kernel/${KERNEL_BINARY}")
  # The osquery kernel was built
  add_dependencies(packages kernel-build)
endif()
