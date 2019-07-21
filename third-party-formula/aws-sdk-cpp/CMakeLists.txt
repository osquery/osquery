# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(awsSdkCppMain)
  set(name "aws-sdk-cpp")
  set(anchor_file lib/libaws-cpp-sdk-ec2.a)

  set(additional_libraries
    lib/libaws-cpp-sdk-firehose.a
    lib/libaws-cpp-sdk-kinesis.a
    lib/libaws-cpp-sdk-sts.a
    lib/libaws-cpp-sdk-core.a
  )

  if(DEFINED PLATFORM_WINDOWS)
    set(anchor_file "lib/aws-cpp-sdk-firehose.lib")
    set(additional_libraries
      lib/aws-cpp-sdk-kinesis.lib
      lib/aws-cpp-sdk-sts.lib
      lib/aws-cpp-sdk-core.lib
    )
  endif()

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}" ${additional_libraries})

  # Might want to skip EC2 on Windows (remove cloud tables).
  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS)
    set(configure_options
      -DCMAKE_LIBRARY_PATH=<INSTALL_DIR>/lib
      -DZLIB_INCLUDE_DIR=<INSTALL_DIR>/include
      -DOPENSSL_INCLUDE_DIR=<INSTALL_DIR>/include
      -DOPENSSL_SSL_LIBRARY=<INSTALL_DIR>/lib/libssl.a
      -DOPENSSL_CRYPTO_LIBRARY=<INSTALL_DIR>/lib/libcrypto.a
      -DBUILD_ONLY=firehose$<SEMICOLON>kinesis$<SEMICOLON>sts$<SEMICOLON>ec2
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    set(configure_options
      -DCMAKE_CXX_FLAGS_RELEASE:STRING=/MT\ /O2\ /Ob2\ /DNDEBUG
      -DFORCE_SHARED_CRT=OFF
      -DBUILD_ONLY=firehose$<SEMICOLON>kinesis$<SEMICOLON>sts
    )
  endif()

  set(dependencies zlib openssl boost)
  definePrebuiltProject(${name}
    URL https://github.com/aws/aws-sdk-cpp/archive/1.6.53.tar.gz
    SHA256 80cb2e1d7012897832dee5d2465ac85b8ad052b520ba4d9bf03aa92e57f7406d
    DEPENDS ${dependencies}
    CONFIGURE
      cmake
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DSTATIC_LINKING=1
        -DNO_HTTP_CLIENT=1
        -DMINIMIZE_SIZE=ON
        -DBUILD_SHARED_LIBS=OFF
        -DENABLE_TESTING=OFF
        -DAUTORUN_UNIT_TESTS=OFF
        ${configure_options}
        <SOURCE_DIR>
    BUILD
      cmake --build . --config Release
    INSTALL
      cmake --build . --config Release --target install
  )
endfunction()

awsSdkCppMain()
