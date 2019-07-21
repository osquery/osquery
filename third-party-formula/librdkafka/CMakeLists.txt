# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(librdkafkaMain)
  set(name "librdkafka")

  if(DEFINED PLATFORM_WINDOWS)
    return()
  endif()

  set(anchor_file "lib/librdkafka.a")

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}" ${additional_lib})

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_openssl)

  set(dependencies zlib openssl rapidjson)
  if(DEFINED PLATFORM_LINUX)
    list(APPEND dependencies bzip2)
  endif()

  definePrebuiltProject(${name}
    URL https://github.com/edenhill/librdkafka/archive/v1.0.1.tar.gz
    SHA256 b2a2defa77c0ef8c508739022a197886e0644bd7bf6179de1b68bdffb02b3550
    DEPENDS ${dependencies}
    PATCHES librdkafka-1.0.1-1.patch
    CONFIGURE
      export LDFLAGS=-L<INSTALL_DIR>/lib &&
      export LIBS=-lcrypto &&
      ./configure
        --prefix=<INSTALL_DIR>
        --disable-sasl
        --disable-gssapi
        --disable-lz4-ext
        --enable-static
    BUILD
      cd src && $(MAKE)
    INSTALL
      cd src && $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

librdkafkaMain()
