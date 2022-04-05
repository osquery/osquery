# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libdpkgMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  #
  # For the sake of completeness, here's the internal libcompat.a
  # library that libdpkg builds.
  #
  # We don't need to actually build it, as we already fullfill all
  # the required functions that the library expects to find.
  #

  #add_library(thirdparty_libdpkg_compat
  #  "${library_root}/lib/compat/md5.c"
  #  "${library_root}/lib/compat/strchrnul.c"
  #  "${library_root}/lib/compat/strnlen.c"
  #  "${library_root}/lib/compat/strndup.c"
  #  "${library_root}/lib/compat/strsignal.c"
  #  "${library_root}/lib/compat/snprintf.c"
  #  "${library_root}/lib/compat/vsnprintf.c"
  #  "${library_root}/lib/compat/asprintf.c"
  #  "${library_root}/lib/compat/vasprintf.c"
  #  "${library_root}/lib/compat/alphasort.c"
  #  "${library_root}/lib/compat/scandir.c"
  #  "${library_root}/lib/compat/unsetenv.c"
  #  "${library_root}/lib/compat/strerror.c"
  #  "${library_root}/lib/compat/empty.c"
  #)
  #
  #target_link_libraries(thirdparty_libdpkg_compat PUBLIC
  #  thirdparty_lzma
  #  thirdparty_zlib
  #  thirdparty_bzip2
  #)
  #
  #target_link_libraries(thirdparty_libdpkg_compat PRIVATE
  #  thirdparty_c_settings
  #)
  #
  #target_compile_definitions(thirdparty_libdpkg_compat PRIVATE
  #  HAVE_CONFIG_H
  #  TEST_LIBCOMPAT=1
  #)
  #
  #target_include_directories(thirdparty_libdpkg_compat PRIVATE
  #  "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}"
  #  "${library_root}/lib/compat"
  #  "${library_root}"
  #)
  #
  #target_include_directories(thirdparty_libdpkg_compat SYSTEM INTERFACE
  #  "${library_root}/lib/compat"
  #)

  add_library(thirdparty_libdpkg_dpkg
    "${library_root}/lib/dpkg/ar.c"
    "${library_root}/lib/dpkg/arch.c"
    "${library_root}/lib/dpkg/atomic-file.c"
    "${library_root}/lib/dpkg/buffer.c"
    "${library_root}/lib/dpkg/c-ctype.c"
    "${library_root}/lib/dpkg/cleanup.c"
    "${library_root}/lib/dpkg/color.c"
    "${library_root}/lib/dpkg/command.c"
    "${library_root}/lib/dpkg/compress.c"
    "${library_root}/lib/dpkg/db-ctrl-access.c"
    "${library_root}/lib/dpkg/db-ctrl-format.c"
    "${library_root}/lib/dpkg/db-ctrl-upgrade.c"
    "${library_root}/lib/dpkg/dbdir.c"
    "${library_root}/lib/dpkg/db-fsys-digest.c"
    "${library_root}/lib/dpkg/db-fsys-divert.c"
    "${library_root}/lib/dpkg/db-fsys-files.c"
    "${library_root}/lib/dpkg/db-fsys-override.c"
    "${library_root}/lib/dpkg/dbmodify.c"
    "${library_root}/lib/dpkg/debug.c"
    "${library_root}/lib/dpkg/deb-version.c"
    "${library_root}/lib/dpkg/depcon.c"
    "${library_root}/lib/dpkg/dir.c"
    "${library_root}/lib/dpkg/dump.c"
    "${library_root}/lib/dpkg/ehandle.c"
    "${library_root}/lib/dpkg/error.c"
    "${library_root}/lib/dpkg/fdio.c"
    "${library_root}/lib/dpkg/fields.c"
    "${library_root}/lib/dpkg/file.c"
    "${library_root}/lib/dpkg/fsys-dir.c"
    "${library_root}/lib/dpkg/fsys-hash.c"
    "${library_root}/lib/dpkg/fsys-iter.c"
    "${library_root}/lib/dpkg/glob.c"
    "${library_root}/lib/dpkg/i18n.c"
    "${library_root}/lib/dpkg/log.c"
    "${library_root}/lib/dpkg/mlib.c"
    "${library_root}/lib/dpkg/namevalue.c"
    "${library_root}/lib/dpkg/nfmalloc.c"
    "${library_root}/lib/dpkg/options.c"
    "${library_root}/lib/dpkg/options-parsers.c"
    "${library_root}/lib/dpkg/pager.c"
    "${library_root}/lib/dpkg/parse.c"
    "${library_root}/lib/dpkg/parsehelp.c"
    "${library_root}/lib/dpkg/path.c"
    "${library_root}/lib/dpkg/path-remove.c"
    "${library_root}/lib/dpkg/pkg-array.c"
    "${library_root}/lib/dpkg/pkg.c"
    "${library_root}/lib/dpkg/pkg-files.c"
    "${library_root}/lib/dpkg/pkg-format.c"
    "${library_root}/lib/dpkg/pkg-hash.c"
    "${library_root}/lib/dpkg/pkg-list.c"
    "${library_root}/lib/dpkg/pkg-namevalue.c"
    "${library_root}/lib/dpkg/pkg-queue.c"
    "${library_root}/lib/dpkg/pkg-show.c"
    "${library_root}/lib/dpkg/pkg-spec.c"
    "${library_root}/lib/dpkg/progname.c"
    "${library_root}/lib/dpkg/program.c"
    "${library_root}/lib/dpkg/progress.c"
    "${library_root}/lib/dpkg/report.c"
    "${library_root}/lib/dpkg/strhash.c"
    "${library_root}/lib/dpkg/string.c"
    "${library_root}/lib/dpkg/strwide.c"
    "${library_root}/lib/dpkg/subproc.c"
    "${library_root}/lib/dpkg/tarfn.c"
    "${library_root}/lib/dpkg/treewalk.c"
    "${library_root}/lib/dpkg/trigdeferred.c"
    "${library_root}/lib/dpkg/triglib.c"
    "${library_root}/lib/dpkg/trigname.c"
    "${library_root}/lib/dpkg/trignote.c"
    "${library_root}/lib/dpkg/utils.c"
    "${library_root}/lib/dpkg/varbuf.c"
    "${library_root}/lib/dpkg/version.c"
  )

  target_link_libraries(thirdparty_libdpkg_dpkg
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_lzma
      thirdparty_zlib
      thirdparty_bzip2
  )

  target_compile_definitions(thirdparty_libdpkg_dpkg PRIVATE
    HAVE_CONFIG_H
    LOCALEDIR="/usr/local/share/locale"
    CONFIGDIR="/usr/local/etc/dpkg"
    ADMINDIR="/usr/local/var/lib/dpkg"
    DEFAULT_TEXT_DOMAIN="dpkg"
  )

  target_include_directories(thirdparty_libdpkg_dpkg PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}"
    "${library_root}/lib/compat"
    "${library_root}"
    "${library_root}/lib"
  )

  target_include_directories(thirdparty_libdpkg_dpkg SYSTEM INTERFACE
    "${library_root}/lib"
  )

  add_library(thirdparty_libdpkg ALIAS thirdparty_libdpkg_dpkg)
endfunction()

libdpkgMain()
