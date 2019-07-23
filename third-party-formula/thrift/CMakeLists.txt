# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(thrifMain)
  set(name "thrift")
  set(anchor_file "lib/libthrift.a")

  set(additional_library
    "lib/libthriftz.a"
  )

  if(DEFINED PLATFORM_WINDOWS)
    set(anchor_file "lib/thriftzmt.lib")

    set(additional_libraries
      lib/thriftmt.lib
    )
  endif()

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}" ${additional_libraries})

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_boost)

  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS)
    set(configure_options
      -DCMAKE_CXX_FLAGS=-fvisibility=hidden\ -fvisibility-inlines-hidden\ $ENV{CXXFLAGS}
    )
  endif()

  set(dependencies boost openssl)
  definePrebuiltProject(${name}
    URL https://github.com/apache/thrift/archive/0.11.0.tar.gz
    SHA256 0e324569321a1b626381baabbb98000c8dd3a59697292dbcc71e67135af0fefd
    PATCHES libthrift-0.11.0-1.patch
    DEPENDS ${dependencies}
    CONFIGURE
      cmake
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DWITH_SHARED_LIB=OFF
        -DBUILD_TESTING=OFF
        -DBUILD_EXAMPLES=OFF
        -DBUILD_C_GLIB=OFF
        -DBUILD_JAVA=OFF
        -DBUILD_PYTHON=OFF
        -DBUILD_HASKELL=OFF
        -DWITH_BOOST_STATIC=ON
        -DWITH_STDTHREADS=OFF
        -DWITH_BOOSTTHREADS=OFF
        -DWITH_OPENSSL=ON
        -DWITH_QT4=OFF
        -DWITH_QT5=OFF
        -DCMAKE_CXX_STANDARD=11
        -DWITH_MT=ON
        -DBOOST_ROOT=<INSTALL_DIR>
        -DZLIB_ROOT=<INSTALL_DIR>
        ${configure_options}
        <SOURCE_DIR>
    BUILD
      cmake --build . --config Release
    INSTALL
      cmake --build . --config Release --target install
  )
endfunction()

thrifMain()
