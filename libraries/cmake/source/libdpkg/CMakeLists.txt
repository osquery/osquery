# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libdpkgMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_libdpkg
    "${library_root}/lib/dpkg/pkg-format.c"
    "${library_root}/lib/dpkg/c-ctype.c"
    "${library_root}/lib/dpkg/report.c"
    "${library_root}/lib/dpkg/utils.c"
    "${library_root}/lib/dpkg/error.c"
    "${library_root}/lib/dpkg/pkg-list.c"
    "${library_root}/lib/dpkg/glob.c"
    "${library_root}/lib/dpkg/log.c"
    "${library_root}/lib/dpkg/progress.c"
    "${library_root}/lib/dpkg/string.c"
    "${library_root}/lib/dpkg/namevalue.c"
    "${library_root}/lib/dpkg/pkg-namevalue.c"
    "${library_root}/lib/dpkg/options.c"
    "${library_root}/lib/dpkg/dbdir.c"
    "${library_root}/lib/dpkg/color.c"
    "${library_root}/lib/dpkg/trigdeferred.c"
    "${library_root}/lib/dpkg/pkg-spec.c"
    "${library_root}/lib/dpkg/tarfn.c"
    "${library_root}/lib/dpkg/buffer.c"
    "${library_root}/lib/dpkg/subproc.c"
    "${library_root}/lib/dpkg/dir.c"
    "${library_root}/lib/dpkg/atomic-file.c"
    "${library_root}/lib/dpkg/options-parsers.c"
    "${library_root}/lib/dpkg/command.c"
    "${library_root}/lib/dpkg/i18n.c"
    "${library_root}/lib/dpkg/fdio.c"
    "${library_root}/lib/dpkg/parsehelp.c"
    "${library_root}/lib/dpkg/trigname.c"
    "${library_root}/lib/dpkg/path-remove.c"
    "${library_root}/lib/dpkg/fields.c"
    "${library_root}/lib/dpkg/triglib.c"
    "${library_root}/lib/dpkg/path.c"
    "${library_root}/lib/dpkg/strwide.c"
    "${library_root}/lib/dpkg/compress.c"
    "${library_root}/lib/dpkg/program.c"
    "${library_root}/lib/dpkg/cleanup.c"
    "${library_root}/lib/dpkg/ar.c"
    "${library_root}/lib/dpkg/ehandle.c"
    "${library_root}/lib/dpkg/strhash.c"
    "${library_root}/lib/dpkg/progname.c"
    "${library_root}/lib/dpkg/t/t-error.c"
    "${library_root}/lib/dpkg/t/t-ar.c"
    "${library_root}/lib/dpkg/t/t-path.c"
    "${library_root}/lib/dpkg/t/t-macros.c"
    "${library_root}/lib/dpkg/t/t-c-ctype.c"
    "${library_root}/lib/dpkg/t/t-string.c"
    "${library_root}/lib/dpkg/t/t-test-skip.c"
    "${library_root}/lib/dpkg/t/t-varbuf.c"
    "${library_root}/lib/dpkg/t/c-trigdeferred.c"
    "${library_root}/lib/dpkg/t/t-test.c"
    "${library_root}/lib/dpkg/t/t-progname.c"
    "${library_root}/lib/dpkg/t/t-buffer.c"
    "${library_root}/lib/dpkg/t/t-trigger.c"
    "${library_root}/lib/dpkg/t/t-version.c"
    "${library_root}/lib/dpkg/t/t-arch.c"
    "${library_root}/lib/dpkg/t/t-mod-db.c"
    "${library_root}/lib/dpkg/t/t-tar.c"
    "${library_root}/lib/dpkg/t/t-pkg-queue.c"
    "${library_root}/lib/dpkg/t/t-subproc.c"
    "${library_root}/lib/dpkg/t/t-command.c"
    "${library_root}/lib/dpkg/t/t-deb-version.c"
    "${library_root}/lib/dpkg/t/t-ehandle.c"
    "${library_root}/lib/dpkg/t/t-pkg-list.c"
    "${library_root}/lib/dpkg/t/c-treewalk.c"
    "${library_root}/lib/dpkg/t/t-pkginfo.c"
    "${library_root}/lib/dpkg/t/c-tarextract.c"
    "${library_root}/lib/dpkg/pkg-db.c"
    "${library_root}/lib/dpkg/dbmodify.c"
    "${library_root}/lib/dpkg/pkg-queue.c"
    "${library_root}/lib/dpkg/varbuf.c"
    "${library_root}/lib/dpkg/pkg-array.c"
    "${library_root}/lib/dpkg/depcon.c"
    "${library_root}/lib/dpkg/version.c"
    "${library_root}/lib/dpkg/trignote.c"
    "${library_root}/lib/dpkg/pkg.c"
    "${library_root}/lib/dpkg/arch.c"
    "${library_root}/lib/dpkg/deb-version.c"
    "${library_root}/lib/dpkg/pkg-show.c"
    "${library_root}/lib/dpkg/mlib.c"
    "${library_root}/lib/dpkg/nfmalloc.c"
    "${library_root}/lib/dpkg/file.c"
    "${library_root}/lib/dpkg/treewalk.c"
    "${library_root}/lib/dpkg/debug.c"
    "${library_root}/lib/dpkg/dump.c"
    "${library_root}/lib/dpkg/parse.c"
    "${library_root}/src/querycmd.c"
    "${library_root}/src/enquiry.c"
    "${library_root}/src/filesdb.c"
    "${library_root}/src/main.c"
    "${library_root}/src/configure.c"
    "${library_root}/src/statcmd.c"
    "${library_root}/src/infodb-access.c"
    "${library_root}/src/packages.c"
    "${library_root}/src/filesdb-hash.c"
    "${library_root}/src/trigproc.c"
    "${library_root}/src/verify.c"
    "${library_root}/src/file-match.c"
    "${library_root}/src/help.c"
    "${library_root}/src/trigcmd.c"
    "${library_root}/src/infodb-format.c"
    "${library_root}/src/select.c"
    "${library_root}/src/errors.c"
    "${library_root}/src/statdb.c"
    "${library_root}/src/filters.c"
    "${library_root}/src/archives.c"
    "${library_root}/src/remove.c"
    "${library_root}/src/cleanup.c"
    "${library_root}/src/selinux.c"
    "${library_root}/src/update.c"
    "${library_root}/src/infodb-upgrade.c"
    "${library_root}/src/divertcmd.c"
    "${library_root}/src/depcon.c"
    "${library_root}/src/unpack.c"
    "${library_root}/src/divertdb.c"
    "${library_root}/src/script.c"
  )

  target_link_libraries(thirdparty_libdpkg PUBLIC
    global_c_settings
    thirdparty_lzma
    thirdparty_zlib
    thirdparty_bzip2
    thirdparty_silence_warnings
  )

  target_compile_definitions(thirdparty_libdpkg PRIVATE
    ADMINDIR_ENVVAR="DPKG_ADMINDIR"
    ADMINDIR="/usr/local/var/lib/dpkg"
    ALT_TMP_EXT=".dpkg-tmp"
    CONFIGDIR="/usr/local/etc/dpkg"
    DEFAULT_TEXT_DOMAIN="dpkg"
    HAVE_CONFIG_H
    LOCALEDIR="/usr/local/share/locale"
    LOGDIR="/usr/local/var/log"
    SYSCONFDIR="/usr/local/etc"
  )

  target_include_directories(thirdparty_libdpkg SYSTEM PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
    "${library_root}/lib/compat"
  )

  target_include_directories(thirdparty_libdpkg SYSTEM PUBLIC
    "${library_root}"
    "${library_root}/lib"
  )
endfunction()

libdpkgMain()
