# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(boostMain)
  set(name "boost")
  set(anchor_file "lib/libboost_chrono-mt.a")

  set(additional_libraries
    lib/libboost_context-mt.a
    lib/libboost_coroutine-mt.a
    lib/libboost_filesystem-mt.a
    lib/libboost_regex-mt.a
    lib/libboost_thread-mt.a
    lib/libboost_system-mt.a
  )

  if(DEFINED PLATFORM_WINDOWS)
    set(anchor_file "lib/libboost_chrono-mt-s.lib")

    set(additional_libraries
      lib/libboost_context-mt-s.lib
      lib/libboost_coroutine-mt-s.lib
      lib/libboost_filesystem-mt-s.lib
      lib/libboost_regex-mt-s.lib
      lib/libboost_thread-mt-s.lib
      lib/libboost_system-mt-s.lib
    )
  endif()

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}" ${additional_libraries})

  set(dependencies zlib)

  if(DEFINED PLATFORM_MACOS)
    set(platform_toolchain darwin)
    set(boost_toolchain clang)
    set(configure_command
      CC=clang ./bootstrap.sh
        --prefix=<INSTALL_DIR>
        --libdir=<INSTALL_DIR>/lib
        --with-toolset=cc &&
      ${REPLACE_CMD} "cc ;" "${platform_toolchain} ;" project-config.jam
    )
    set(cxx_flags "cxxflags=-std=c++11 -fvisibility=hidden -fvisibility-inlines-hidden $ENV{CXXFLAGS}")
    set(link_flags optimization=space "linkflags=$ENV{LDFLAGS}")
  elseif(DEFINED PLATFORM_LINUX)
    list(APPEND dependencies bzip2)
    set(platform_toolchain clang)
    set(boost_toolchain clang)
    set(configure_command
      CC=clang ./bootstrap.sh
        --prefix=<INSTALL_DIR>
        --libdir=<INSTALL_DIR>/lib
        --with-toolset=cc &&
      ${REPLACE_CMD} "cc ;" "${platform_toolchain} ;" project-config.jam
    )
    set(cxx_flags "cxxflags=-std=c++11 -fvisibility=hidden -fvisibility-inlines-hidden $ENV{CXXFLAGS}")
    set(link_flags optimization=space "linkflags=$ENV{LDFLAGS}")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(boost_toolchain msvc-14.1)
    set(configure_command bootstrap.bat)
    set(link_flags runtime-link=static)
  endif()

  definePrebuiltProject(${name}
    URL https://downloads.sourceforge.net/project/boost/boost/1.66.0/boost_1_66_0.tar.bz2
    SHA256 5721818253e6a0989583192f96782c4a98eb6204965316df9f5ad75819225ca9
    DEPENDS ${dependencies}
    CONFIGURE
      ${configure_command}
    BUILD true
    INSTALL
      ./b2 install
        --prefix=<INSTALL_DIR>
        --libdir=<INSTALL_DIR>/lib
        -d2
        --layout=tagged
        --ignore-site-config
        --disable-icu
        --with-filesystem
        --with-regex
        --with-system
        --with-thread
        --with-coroutine
        --with-context
        threading=multi
        link=static
        variant=release
        toolset=${boost_toolchain}
        address-model=64
        include=<INSTALL_DIR>/include
        ${link_flags}
        ${cxx_flags}
    BUILD_IN_SOURCE ON
  )
endfunction()

boostMain()
