project(thirdparty_openssl)

set(OPENSSL_VERSION "1.1.1g")
set(OPENSSL_ARCHIVE_SHA256 "ddb04774f1e32f0c49751e21b67216ac87852ceb056b75209af2443400636d46")

include(ExternalProject)

function(opensslMain)

  set(common_options
    no-ssl2
    no-ssl3
    no-asm
    no-shared
    no-weak-ssl-ciphers
    no-comp
    enable-cms
  )

  add_library(thirdparty_openssl_ssl STATIC IMPORTED GLOBAL)
  add_library(thirdparty_openssl_crypto STATIC IMPORTED GLOBAL)

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    set(configure_command
      "${CMAKE_COMMAND}" -E env "CC=${CMAKE_C_COMPILER}" "AR=${CMAKE_AR}"
      perl ./Configure linux-${TARGET_PROCESSOR}
        ${common_options}
        ${OSQUERY_FORMULA_CFLAGS}

        "--prefix=${install_prefix}"
        "--openssldir=${install_prefix}/etc/openssl"

        -fPIC
        --sysroot=${CMAKE_SYSROOT}
        -lunwind
        -lpthread
    )

    set(build_command
      "${CMAKE_COMMAND}" -E make_directory "${install_prefix}/etc/openssl" &&
      make depend &&
      make
    )

    set(install_command
      make install_sw install_ssldirs
    )

    set(openssl_libs
      "${install_prefix}/lib/libssl.a"
      "${install_prefix}/lib/libcrypto.a"
    )

    set_target_properties(thirdparty_openssl_ssl PROPERTIES IMPORTED_LOCATION
      "${install_prefix}/lib/libssl.a"
    )
    set_target_properties(thirdparty_openssl_crypto PROPERTIES IMPORTED_LOCATION
      "${install_prefix}/lib/libcrypto.a"
    )

  elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    set(platform_c_flags
      -fPIC
    )

    if(NOT "${CMAKE_OSX_DEPLOYMENT_TARGET}" STREQUAL "")
      list(APPEND platform_c_flags
        -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}
      )
    endif()

    set(configure_command
      "${CMAKE_COMMAND}" -E env "CC=${CMAKE_C_COMPILER}" "AR=${CMAKE_AR}"
      perl ./Configure darwin64-x86_64-cc
        ${common_options}
        ${OSQUERY_FORMULA_CFLAGS}

        "--prefix=${install_prefix}"
        "--openssldir=${install_prefix}/etc/openssl"

        enable-ec_nistp_64_gcc_128
        ${platform_c_flags}
    )

    # Don't be afraid to manually patch the build scripts; for some settings, there is no
    # other way.
    # see https://wiki.openssl.org/index.php/Compilation_and_Installation#Modifying_Build_Settings
    set(build_command
      /usr/bin/sed -i ".bak" "s+^CFLAGS=+CFLAGS=-isysroot ${CMAKE_OSX_SYSROOT} +g" "Makefile" &&
        "${CMAKE_COMMAND}" -E make_directory "${install_prefix}/etc/openssl" &&
        make depend &&
        make
    )

    set(install_command
      make install_sw install_ssldirs
    )

    set(openssl_libs
      "${install_prefix}/lib/libssl.a"
      "${install_prefix}/lib/libcrypto.a"
    )

    set_target_properties(thirdparty_openssl_ssl PROPERTIES IMPORTED_LOCATION
      "${install_prefix}/lib/libssl.a"
    )
    set_target_properties(thirdparty_openssl_crypto PROPERTIES IMPORTED_LOCATION
      "${install_prefix}/lib/libcrypto.a"
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
      "${CMAKE_COMMAND}" -E env "cmd.exe" "/C" "nmake PERL=${perl_executable_path}"
    )

    set(install_command
      "${CMAKE_COMMAND}" -E make_directory "${install_prefix}/lib" &&
      "${CMAKE_COMMAND}" -E copy "./libssl.lib" "${install_prefix}/lib" &&
      "${CMAKE_COMMAND}" -E copy "./libcrypto.lib" "${install_prefix}/lib" &&
      "${CMAKE_COMMAND}" -E make_directory "${install_prefix}/include" &&
      "${CMAKE_COMMAND}" -E copy_directory "./include/openssl" "${install_prefix}/include/openssl" &&
      "${CMAKE_COMMAND}" -E remove "${install_prefix}/include/openssl/__DECC_INCLUDE_PROLOGUE.h"
                                   "${install_prefix}/include/openssl/__DECC_INCLUDE_EPILOGUE.h"
                                   "${install_prefix}/include/openssl/opensslconf.h.in"
    )

    set(openssl_libs
      "${install_prefix}/lib/libssl.lib"
      "${install_prefix}/lib/libcrypto.lib"
    )

    set_target_properties(thirdparty_openssl_ssl PROPERTIES IMPORTED_LOCATION
      "${install_prefix}/lib/libssl.lib"
    )
    set_target_properties(thirdparty_openssl_crypto PROPERTIES IMPORTED_LOCATION
      "${install_prefix}/lib/libcrypto.lib"
    )

  else()
    message(FATAL_ERROR "Unsupported system")
  endif()

  list(APPEND openssl_c_flags ${OSQUERY_FORMULA_CFLAGS})
  string(REPLACE ";" " " openssl_c_flags "${openssl_c_flags}")

  string(REGEX MATCH "[0-9]\.[0-9]\.[0-9]" OPENSSL_VERSION_NO_PATCH "${OPENSSL_VERSION}")

  set(openssl_urls
    "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
    "https://www.openssl.org/source/old/${OPENSSL_VERSION_NO_PATCH}/openssl-${OPENSSL_VERSION}.tar.gz"
  )

  ExternalProject_Add(openssl
    URL "${openssl_urls}"
    URL_HASH SHA256=${OPENSSL_ARCHIVE_SHA256}
    CONFIGURE_COMMAND ${configure_command}
    BUILD_COMMAND ${build_command}
    INSTALL_COMMAND ""
    BUILD_IN_SOURCE true
    EXCLUDE_FROM_ALL true
  )

  ExternalProject_Get_property(openssl SOURCE_DIR)

  ExternalProject_Add_Step(openssl custom_install
    COMMAND ${install_command}
    DEPENDEES build
    BYPRODUCTS ${openssl_libs}
    WORKING_DIRECTORY "${SOURCE_DIR}"
  )

  add_library(thirdparty_openssl INTERFACE)

  add_dependencies(thirdparty_openssl_ssl openssl)
  add_dependencies(thirdparty_openssl_crypto openssl)

  target_include_directories(thirdparty_openssl INTERFACE "${install_prefix}/include")
  target_link_libraries(thirdparty_openssl INTERFACE
    thirdparty_openssl_ssl
    thirdparty_openssl_crypto
  )
endfunction()

opensslMain()
