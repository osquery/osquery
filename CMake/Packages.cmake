# make package
if(APPLE)
  add_custom_target(
    packages
    "${CMAKE_SOURCE_DIR}/tools/deployment/make_osx_package.sh"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Building default OS X package (no custom config)" VERBATIM
  )
elseif(LINUX)
  if(UBUNTU)
    set(PACKAGE_TYPE "deb")
    set(PACKAGE_DEPENDENCIES
      "libc6 (>=2.15)"
      "zlib1g"
      "libbz2-1.0"
      "libapt-pkg4.12"
      "libreadline6"
    )
    if(OSQUERY_BUILD_DISTRO STREQUAL "PRECISE")
      set(PACKAGE_ITERATION "1.ubuntu12.04")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libstdc++6"
        "libudev0"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "TRUSTY")
      set(PACKAGE_ITERATION "1.ubuntu14.04")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libstdc++6 (>= 4.8)"
        "libudev1"
      )
    endif()
  elseif(CENTOS)
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
    if(OSQUERY_BUILD_DISTRO STREQUAL "CENTOS6")
      set(PACKAGE_ITERATION "1.el6_6.5")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libudev"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "CENTOS7")
      set(PACKAGE_ITERATION "1.el7_7.0")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "systemd-devel"
        "epel-release"
      )
    endif()
  elseif(RHEL)
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
    if(OSQUERY_BUILD_DISTRO STREQUAL "RHEL6")
      set(PACKAGE_ITERATION "1.el6_6.5")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "libudev"
      )
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "RHEL7")
      set(PACKAGE_ITERATION "1.el7_7.0")
      set(PACKAGE_DEPENDENCIES
        "${PACKAGE_DEPENDENCIES}"
        "systemd-devel"
        "epel-release"
      )
    endif()
  endif()
  JOIN("${PACKAGE_DEPENDENCIES}" ", " PACKAGE_DEPENDENCIES)

  add_custom_target(
    packages
    "${CMAKE_SOURCE_DIR}/tools/deployment/make_linux_package.sh"
      -t ${PACKAGE_TYPE} -i "${PACKAGE_ITERATION}"
      -d "${PACKAGE_DEPENDENCIES}"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Building linux packages (no custom config)" VERBATIM
  )
endif()
