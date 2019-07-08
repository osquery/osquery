# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(augeasMain)
  set(name "augeas")

  if(DEFINED PLATFORM_WINDOWS)
    add_osquery_library(thirdparty_augeas INTERFACE)
    return()
  endif()

  set(anchor_file "lib/libaugeas.a")

  set(additional_library
    "lib/libfa.a"
  )

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}" ${additional_library})

  set(dependencies libxml2)
  definePrebuiltProject(${name}
    URL http://download.augeas.net/augeas-1.12.0.tar.gz
    SHA256 321942c9cc32185e2e9cb72d0a70eea106635b50269075aca6714e3ec282cb87
    DEPENDS ${dependencies}
    PATCHES libaugeas-1.12.0-1.patch
    CONFIGURE
      autoreconf &&
      ./configure
        --prefix=<INSTALL_DIR>
        --enable-shared=no
        --without-selinux
    BUILD
      cd <SOURCE_DIR>/gnulib/lib && $(MAKE) &&
      cd <SOURCE_DIR>/src &&
        $(MAKE) datadir.h &&
        $(MAKE) install-libLTLIBRARIES &&
        $(MAKE) install-data-am
    INSTALL
      $(MAKE) install-data-am
    BUILD_IN_SOURCE ON
  )
endfunction()

augeasMain()
