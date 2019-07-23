# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(berkeleydbMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "berkeley-db")
  set(anchor_file "lib/libdb.a")

  set(additional_libraries
    lib/libdb-5.3.a
    lib/libdb_cxx-5.3.a
    lib/libdb_cxx.a
  )

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}" ${additional_libraries})

  set(dependencies libxml2)
  definePrebuiltProject(${name}
    URL http://pkgs.fedoraproject.org/repo/pkgs/libdb/db-5.3.28.tar.gz/b99454564d5b4479750567031d66fe24/db-5.3.28.tar.gz
    SHA256 e0a992d740709892e81f9d93f06daf305cf73fb81b545afe72478043172c3628
    DEPENDS ${dependencies}
    PATCHES berkeley-db-5.3.28-1.patch
    CONFIGURE
      cd build_unix && ../dist/configure
        --disable-debug
        --prefix=<INSTALL_DIR>
        --enable-cxx
        --enable-compat185
        --disable-shared
        --enable-static
    BUILD
      cd build_unix && $(MAKE)
    INSTALL
      cd build_unix && $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

berkeleydbMain()
