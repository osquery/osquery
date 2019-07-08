# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(librpmMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "librpm")
  set(anchor_file "lib/librpm.a")

  set(additional_libraries
    lib/librpmbuild.a
    lib/librpmio.a
    lib/librpmsign.a
  )

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}" ${additional_libraries})

  target_link_libraries("thirdparty_${name}" INTERFACE
    thirdparty_berkeley-db
    thirdparty_bzip2
    thirdparty_lzma
    thirdparty_openssl
    thirdparty_popt
    thirdparty_zlib
  )

  target_link_libraries("thirdparty_${name}_librpm" INTERFACE
    "thirdparty_${name}_librpmio"
  )

  target_link_libraries("thirdparty_${name}_librpmio" INTERFACE thirdparty_zlib)
  target_link_libraries("thirdparty_${name}_librpmio" INTERFACE thirdparty_bzip2)

  if(DEFINED PLATFORM_MACOS)
    set(extra_libs "-lz -liconv")
    set(extra_patches librpm-4.14.1-1-darwin.patch)
  endif()

  set(dependencies openssl popt berkeley-db libmagic)
  definePrebuiltProject(${name}
    URL http://ftp.rpm.org/releases/rpm-4.14.x/rpm-4.14.1.tar.bz2
    SHA256 43f40e2ccc3ca65bd3238f8c9f8399d4957be0878c2e83cba2746d2d0d96793b
    DEPENDS ${dependencies}
    PATCHES
      librpm-4.14.1-1.patch
      ${extra_patches}
    CONFIGURE
      export LIBS=${extra_libs} &&
      ./configure
        --prefix=<INSTALL_DIR>
        --with-external-db
        --without-selinux
        --without-lua
        --without-cap
        --without-archive
        --disable-nls
        --disable-rpath
        --disable-plugins
        --disable-python
        --enable-zstd=no
        --with-crypto=openssl
        --disable-shared
        --enable-static
    BUILD
      $(MAKE)
    INSTALL
      $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

librpmMain()
