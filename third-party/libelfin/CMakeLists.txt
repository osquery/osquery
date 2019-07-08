# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libelfinMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libelfin")
  set(anchor_file "lib/libdwarf++.a")

  set(additional_lib
    lib/libelf++.a
  )

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}" ${additional_lib})

  definePrebuiltProject(${name}
    URL https://github.com/aclements/libelfin/archive/v0.3.tar.gz
    SHA256 c338942b967582922b3514b54b93175ca9051a9668db92dd8ef619824d443ac7
    CONFIGURE true
    BUILD
      export CXXFLAGS=-Wno-unused-command-line-argument\ $ENV{CXXFLAGS} &&
      $(MAKE)
    INSTALL
      $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

libelfinMain()
