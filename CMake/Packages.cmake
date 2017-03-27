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
  add_custom_target(
    packages
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Building linux packages (no custom config)" VERBATIM
    DEPENDS daemon shell
  )

  set(DEB_PACKAGE_DEPENDENCIES "libc6 (>=2.12), zlib1g")
  set(RPM_PACKAGE_DEPENDENCIES "glibc >= 2.12, zlib")
  set(PACMAN_PACKAGE_DEPENDENCIES "zlib")

  find_program(FPM_EXECUTABLE "fpm" ENV PATH)
  find_program(RPMBUILD_EXECUTABLE "rpmbuild" ENV PATH)
  find_program(BSDTAR_EXECUTABLE "bsdtar" ENV PATH)

  if(FPM_EXECUTABLE)
    add_custom_command(TARGET packages PRE_BUILD
      COMMAND bash "${CMAKE_SOURCE_DIR}/tools/deployment/make_linux_package.sh"
        -t "deb" -i "1.linux" -d '${DEB_PACKAGE_DEPENDENCIES}'
    )

    if(RPMBUILD_EXECUTABLE)
      add_custom_command(TARGET packages PRE_BUILD
        COMMAND bash "${CMAKE_SOURCE_DIR}/tools/deployment/make_linux_package.sh"
          -t "rpm" -i "1.linux" -d '${RPM_PACKAGE_DEPENDENCIES}'
      )
    else()
      WARNING_LOG("Skipping RPM/CentOS packages: Cannot find rpmbuild")
    endif()

    if(BSDTAR_EXECUTABLE)
      add_custom_command(TARGET packages PRE_BUILD
        COMMAND bash "${CMAKE_SOURCE_DIR}/tools/deployment/make_linux_package.sh"
          -t "pacman" -i "1.arch" -d '${PACMAN_PACKAGE_DEPENDENCIES}'
      )
    else()
      WARNING_LOG("Skipping ArchLinux packages: Cannot find bsdtar")
    endif()

    add_custom_command(TARGET packages PRE_BUILD
      COMMAND bash "${CMAKE_SOURCE_DIR}/tools/deployment/make_linux_package.sh"
        -t "tar" -i "1.linux" -d "none"
    )

  else()
    WARNING_LOG("Cannot find fpm executable in path")
  endif()

endif()

if(NOT DEFINED KERNEL_BINARY)
  message(FATAL_ERROR "Package related targets must be included after kernel")
endif()

# Add dependencies and additional package data based on optional components.
if(EXISTS "${CMAKE_BINARY_DIR}/kernel/${KERNEL_BINARY}")
  # The osquery kernel was built
  add_dependencies(packages kernel-build)
endif()
