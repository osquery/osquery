# make package
if(APPLE)
  add_custom_target(
    packages
    COMMAND bash "${CMAKE_SOURCE_DIR}/tools/deployment/make_osx_package.sh"
    COMMAND ${PYTHON_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tools/codegen/genapi.py" "${CMAKE_SOURCE_DIR}"
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
      "libc6 (>=2.13)"
      "zlib1g"
    )

    if(OSQUERY_BUILD_DISTRO STREQUAL "precise")
      set(PACKAGE_ITERATION "1.ubuntu12")
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "wheezy")
      set(PACKAGE_ITERATION "1.debian7")
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "trusty")
      set(PACKAGE_ITERATION "1.ubuntu14")
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "jessie")
      set(PACKAGE_ITERATION "1.debian8")
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "xenial")
      set(PACKAGE_ITERATION "1.ubuntu16")
    endif()
  elseif(REDHAT_BASED)
    set(PACKAGE_TYPE "rpm")
    set(PACKAGE_ITERATION "1.el")
    set(PACKAGE_DEPENDENCIES
      "glibc >= 2.12"
      "zlib"
    )
    if(OSQUERY_BUILD_DISTRO STREQUAL "centos6")
      set(PACKAGE_ITERATION "1.el6")
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "rhel6")
      set(PACKAGE_ITERATION "1.rhel6")
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "scientific6")
      set(PACKAGE_ITERATION "1.el6")
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "oracle6")
      set(PACKAGE_ITERATION "1.oel6")
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "centos7")
      set(PACKAGE_ITERATION "1.el7")
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "rhel7")
      set(PACKAGE_ITERATION "1.rhel7")
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "scientific7")
      set(PACKAGE_ITERATION "1.el7")
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "oracle7")
      set(PACKAGE_ITERATION "1.oel7")
    elseif(OSQUERY_BUILD_DISTRO STREQUAL "amazon2015.03")
      set(PACKAGE_ITERATION "1.amazon2015")
    endif()
  endif()
  JOIN("${PACKAGE_DEPENDENCIES}" ", " PACKAGE_DEPENDENCIES)

  add_custom_target(
    packages
    COMMAND bash "${CMAKE_SOURCE_DIR}/tools/deployment/make_linux_package.sh"
      -t ${PACKAGE_TYPE} -i "${PACKAGE_ITERATION}"
      -d "${PACKAGE_DEPENDENCIES}"
    COMMAND ${PYTHON_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tools/codegen/genapi.py" "${CMAKE_SOURCE_DIR}"
      "--output" "--directory" "${CMAKE_BINARY_DIR}"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Building linux packages (no custom config)" VERBATIM
    DEPENDS daemon shell
  )
endif()

if(NOT DEFINED KERNEL_BINARY)
  message(FATAL_ERROR "Package related targets must be included after kernel")
endif()

# Add dependencies and additional package data based on optional components.
if(EXISTS "${CMAKE_BINARY_DIR}/kernel/${KERNEL_BINARY}")
  # The osquery kernel was built
  add_dependencies(packages kernel-build)
endif()
