cmake_minimum_required(VERSION 3.14.6)
project(thirdparty_openssl)

# NOTE: Updating to 1.1.1d should be easy:
# 1. Increase the OPENSSL_VERSION value
# 2. Update the 'sed' patching in macOS to update CFLAGS (rather than CFLAG)
# 3. Remove the call to the do_nt.bat script
# 4. Update the Windows library names to libssl/libcrypto

set(OPENSSL_VERSION "1.0.2t")

include(ExternalProject)

function(opensslMain)
  generateMetadataTargets()

  if(NOT DEFINED thirdparty_zlib_INCLUDE_DIRS OR
     NOT DEFINED thirdparty_zlib_LIBRARIES)
    message(WARNING "The zlib dependency was not specified correctly")
    return()
  endif()

  set(common_options
    no-ssl2
    no-ssl3
    no-asm
    no-shared
    no-weak-ssl-ciphers
    zlib-dynamic
    enable-cms
    "--with-zlib-include=${thirdparty_zlib_INCLUDE_DIRS}"
    "--with-zlib-lib=${thirdparty_zlib_LIBRARIES}"
  )

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    set(configure_command
      "${CMAKE_COMMAND}" -E env CC="${CMAKE_C_COMPILER}" AR="${CMAKE_AR}"
      perl ./Configure linux-x86_64
        ${common_options}
        ${C_FLAGS}

        "--prefix=${CMAKE_INSTALL_PREFIX}"
        "--openssldir=${CMAKE_INSTALL_PREFIX}/etc/openssl"

        -fPIC
        --sysroot=${CMAKE_SYSROOT}
        -lunwind
        -lpthread
    )

    set(build_command
      "${CMAKE_COMMAND}" -E make_directory "${CMAKE_INSTALL_PREFIX}/etc/openssl" &&
      make depend &&
      make
    )

    set(optional_install_command
      make install
    )

  elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    set(configure_command
      "${CMAKE_COMMAND}" -E env CC="${CMAKE_C_COMPILER}" AR="${CMAKE_AR}"
      perl ./Configure darwin64-x86_64-cc
        ${common_options}
        ${C_FLAGS}

        "--prefix=${CMAKE_INSTALL_PREFIX}"
        "--openssldir=${CMAKE_INSTALL_PREFIX}/etc/openssl"

        enable-ec_nistp_64_gcc_128
        -fPIC
    )

    # Don't be afraid to manually patch the build scripts; for some settings, there is no
    # other way.
    # see https://wiki.openssl.org/index.php/Compilation_and_Installation#Modifying_Build_Settings
    set(build_command
      /usr/bin/sed -i ".bak" "s+^CFLAG=+CFLAG=-isysroot ${CMAKE_OSX_SYSROOT} +g" "Makefile" &&
        "${CMAKE_COMMAND}" -E make_directory "${CMAKE_INSTALL_PREFIX}/etc/openssl" &&
        make depend &&
        make
    )

    set(optional_install_command
      make install
    )

  elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    set(CMAKE_PREFIX_PATH "C:\\Strawberry\\perl\\bin")
    find_package(Perl REQUIRED)

    set(configure_command
      "${CMAKE_COMMAND}" -E env
      "${PERL_EXECUTABLE}" Configure VC-WIN64A
      ${common_options}
    )

    get_filename_component(perl_bin_path "${PERL_EXECUTABLE}" DIRECTORY)

    string(REPLACE "/" "\\\\" perl_executable_path "${PERL_EXECUTABLE}")

    set(build_command
      cmake -E env "PATH=${perl_bin_path}" "cmd.exe" "/C" "ms\\do_nt.bat" &&
      "cmd.exe" "/C" "nmake /f ms\\nt.mak PERL=${perl_executable_path}"
    )

    set(install_command
      "${CMAKE_COMMAND}" -E make_directory "${CMAKE_INSTALL_PREFIX}/lib" &&
      "${CMAKE_COMMAND}" -E copy "out32/libeay32.lib" "${CMAKE_INSTALL_PREFIX}/lib" &&
      "${CMAKE_COMMAND}" -E copy "out32/ssleay32.lib" "${CMAKE_INSTALL_PREFIX}/lib" &&
      "${CMAKE_COMMAND}" -E make_directory "${CMAKE_INSTALL_PREFIX}/include" &&
      "${CMAKE_COMMAND}" -E copy_directory "inc32/openssl" "${CMAKE_INSTALL_PREFIX}/include/openssl"
    )

  else()
    message(FATAL_ERROR "Unsupported system")
  endif()

  list(APPEND openssl_c_flags ${C_FLAGS})
  string(REPLACE ";" " " openssl_c_flags "${openssl_c_flags}")

  ExternalProject_Add(openssl
    URL "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
    CONFIGURE_COMMAND ${configure_command}
    BUILD_COMMAND ${build_command}
    INSTALL_COMMAND ${install_command}
    BUILD_IN_SOURCE true
  )
endfunction()

function(generateMetadataTargets)
  set(metadata_version "${OPENSSL_VERSION}")
  set(metadata_revision "1")
  set(metadata_dependencies "thirdparty_zlib")

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    set(metadata_libraries
      "lib/libeay32.lib"
      "lib/ssleay32.lib"
    )

  else()
    set(metadata_libraries
      "lib/libssl.a"
      "lib/libcrypto.a"
    )
  endif()

  set(metadata_field_list
    metadata_version
    metadata_revision
    metadata_dependencies
    metadata_libraries
  )

  foreach(metadata_field ${metadata_field_list})
    add_custom_target(
      "${metadata_field}"
      COMMAND "${CMAKE_COMMAND}" -E echo "${metadata_field}:[${${metadata_field}}]"
      VERBATIM
    )
  endforeach()
endfunction()

opensslMain()
