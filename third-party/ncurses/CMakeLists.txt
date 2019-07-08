# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libncursesMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "ncurses")

  definePrebuiltProject(${name}
    URL http://ftpmirror.gnu.org/ncurses/ncurses-6.0.tar.gz
    SHA256 f551c24b30ce8bfb6e96d9f59b42fbea30fa3a6123384172f9e7284bcf647260
    CONFIGURE
      ./configure
        --prefix=<INSTALL_DIR>
        --enable-symlinks
        --without-shared
        --without-manpages
        --with-gmp=no
        --with-static
    BUILD
      $(MAKE)
    INSTALL
      $(MAKE) install &&
      ln -sf ncurses/curses.h <INSTALL_DIR>/include/curses.h &&
      ln -sf ncurses/term.h <INSTALL_DIR>/include/term.h
    BUILD_IN_SOURCE ON
  )
endfunction()

libncursesMain()
