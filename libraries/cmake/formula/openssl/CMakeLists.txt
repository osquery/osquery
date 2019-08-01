cmake_minimum_required(VERSION 3.14.5)
project(thirdparty_openssl)

include(ExternalProject)

function(opensslMain)
  generateMetadataTargets()

  if(NOT DEFINED thirdparty_zlib_INCLUDE_DIRS OR
     NOT DEFINED thirdparty_zlib_LIBRARIES)

    message(WARNING "The zlib dependency was not specified correctly")
    return()
  endif()

  # TODO(alessandro): Port all the settings from the original formula AND make sure it uses CMAKE_C_COMPILER
  ExternalProject_Add(
    openssl
    URL "http://www.openssl.org/source/openssl-1.0.2o.tar.gz"

    CONFIGURE_COMMAND
      perl ./Configure "--prefix=${CMAKE_INSTALL_PREFIX}"
        "--openssldir=${CMAKE_INSTALL_PREFIX}/etc/openssl"
        no-ssl2
        no-ssl3
        no-asm
        no-shared
        no-weak-ssl-ciphers
        zlib-dynamic
        enable-cms
        "--with-zlib-include=${thirdparty_zlib_INCLUDE_DIRS}"
        "--with-zlib-lib=${thirdparty_zlib_LIBRARIES}"
        linux-x86_64

    BUILD_COMMAND
      "${CMAKE_COMMAND}" -E make_directory "${CMAKE_INSTALL_PREFIX}/etc/openssl" &&
      $(MAKE) depend -j 10 &&
      $(MAKE) -j 10

    INSTALL_COMMAND
      $(MAKE) install

    BUILD_IN_SOURCE true
  )
endfunction()

function(generateMetadataTargets)
  set(metadata_version "1.0.2o")
  set(metadata_revision "1")
  set(metadata_dependencies "thirdparty_zlib")

  set(metadata_libraries
    "lib/libssl.a"
    "lib/libcrypto.a"
  )

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
