# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(librpmMain)
  set(library_root "${OSQUERY_librpm_ROOT_DIR}")

  set(rpm_library_srcs
    "${library_root}/lib/backend/bdb_ro.c"
    "${library_root}/lib/backend/sqlite.c"
    "${library_root}/lib/backend/dbi.c"
    "${library_root}/lib/backend/dummydb.c"
    "${library_root}/lib/backend/dbiset.c"
    "${library_root}/lib/backend/ndb/glue.c"
    "${library_root}/lib/backend/ndb/rpmidx.c"
    "${library_root}/lib/backend/ndb/rpmpkg.c"
    "${library_root}/lib/backend/ndb/rpmxdb.c"
    "${library_root}/lib/header.c"
    "${library_root}/lib/headerfmt.c"
    "${library_root}/lib/headerutil.c"
    "${library_root}/lib/rpmdb.c"
    "${library_root}/lib/fprint.c"
    "${library_root}/lib/tagname.c"
    "${library_root}/lib/rpmtd.c"
    "${library_root}/lib/cpio.c"
    "${library_root}/lib/depends.c"
    "${library_root}/lib/order.c"
    "${library_root}/lib/formats.c"
    "${library_root}/lib/tagexts.c"
    "${library_root}/lib/fsm.c"
    "${library_root}/lib/manifest.c"
    "${library_root}/lib/package.c"
    "${library_root}/lib/poptALL.c"
    "${library_root}/lib/poptI.c"
    "${library_root}/lib/poptQV.c"
    "${library_root}/lib/psm.c"
    "${library_root}/lib/query.c"
    "${library_root}/lib/rpmal.c"
    "${library_root}/lib/rpmchecksig.c"
    "${library_root}/lib/rpmds.c"
    "${library_root}/lib/rpmfi.c"
    "${library_root}/lib/rpmgi.c"
    "${library_root}/lib/rpminstall.c"
    "${library_root}/lib/rpmlead.c"
    "${library_root}/lib/rpmps.c"
    "${library_root}/lib/rpmprob.c"
    "${library_root}/lib/rpmrc.c"
    "${library_root}/lib/rpmte.c"
    "${library_root}/lib/rpmts.c"
    "${library_root}/lib/rpmfs.c"
    "${library_root}/lib/signature.c"
    "${library_root}/lib/transaction.c"
    "${library_root}/lib/verify.c"
    "${library_root}/lib/rpmlock.c"
    "${library_root}/lib/relocation.c"
    "${library_root}/lib/rpmchroot.c"
    "${library_root}/lib/rpmplugins.c"
    "${library_root}/lib/rpmug.c"
    "${library_root}/lib/rpmtriggers.c"
    "${library_root}/lib/rpmvs.c"
  )

  set(rpmbuild_library_srcs
    "${library_root}/build/build.c"
    "${library_root}/build/files.c"
    "${library_root}/build/misc.c"
    "${library_root}/build/pack.c"
    "${library_root}/build/parseSimpleScript.c"
    "${library_root}/build/parseChangelog.c"
    "${library_root}/build/parseDescription.c"
    "${library_root}/build/parseFiles.c"
    "${library_root}/build/parsePreamble.c"
    "${library_root}/build/parsePrep.c"
    "${library_root}/build/parseReqs.c"
    "${library_root}/build/parseSpec.c"
    "${library_root}/build/parseList.c"
    "${library_root}/build/reqprov.c"
    "${library_root}/build/rpmfc.c"
    "${library_root}/build/spec.c"
    "${library_root}/build/parsePolicies.c"
    "${library_root}/build/policies.c"
  )

  set(rpmio_library_srcs
    "${library_root}/rpmio/argv.c"
    "${library_root}/rpmio/base64.c"
    "${library_root}/rpmio/digest.c"
    "${library_root}/rpmio/expression.c"
    "${library_root}/rpmio/macro.c"
    "${library_root}/rpmio/rpmhook.c"
    "${library_root}/rpmio/rpmio.c"
    "${library_root}/rpmio/rpmlog.c"
    "${library_root}/rpmio/rpmmalloc.c"
    "${library_root}/rpmio/rgetopt.c"
    "${library_root}/rpmio/rpmpgp.c"
    "${library_root}/rpmio/rpmsq.c"
    "${library_root}/rpmio/rpmsw.c"
    "${library_root}/rpmio/url.c"
    "${library_root}/rpmio/rpmstring.c"
    "${library_root}/rpmio/rpmfileutil.c"
    "${library_root}/rpmio/rpmglob.c"
    "${library_root}/rpmio/rpmkeyring.c"
    "${library_root}/rpmio/rpmstrpool.c"
    "${library_root}/rpmio/rpmver.c"
    "${library_root}/rpmio/rpmvercmp.c"
    "${library_root}/rpmio/digest_openssl.c"
    "${library_root}/rpmio/rpmpgp_internal.c"
  )

  set(rpmmisc_library_srcs
    "${library_root}/misc/fts.c"
    "${library_root}/misc/fnmatch.c"
  )

  set(rpmsign_library_srcs
    "${library_root}/sign/rpmgensig.c"
  )

  add_library(thirdparty_librpm
    ${rpm_library_srcs}
    ${rpmbuild_library_srcs}
    ${rpmio_library_srcs}
    ${rpmmisc_library_srcs}
    ${rpmsign_library_srcs}
  )

  target_compile_options(thirdparty_librpm PRIVATE
    -fno-strict-aliasing
    -fno-strict-overflow
  )

  target_compile_definitions(thirdparty_librpm PRIVATE
    HAVE_CONFIG_H
    LIBRPMALIAS_EXECPATH="/usr/local/bin"
    LIBRPMALIAS_FILENAME="rpmpopt-4.18.0"
    LOCALEDIR="/usr/local/share/locale"
    LOCALSTATEDIR="/usr/local/var"
    RPMCONFIGDIR="/usr/local/lib/rpm"
    SYSCONFDIR="/usr/local/etc"
  )

  # Starting in glibc 2.25, the macros `major` and `minor` were moved
  # from `<sys/types.h>` to `<sys/sysmacros.h>`, to stop leaking these
  # common words into the global namespace of those including <stdlib.h>
  #
  # https://sourceware.org/bugzilla/show_bug.cgi?format=multiple&id=19239
  #
  # The macros MAJOR_IN_MKDEV and MAJOR_IN_SYSMACROS would be defined if
  # necessary by autoconfig, and put in `config.h`. But osquery build
  # uses CMake instead of autotools, with a git-committed `config.h`.
  # This mirrors detection done by autoconf/headers.m4 as CMake code.
  #
  if(DEFINED PLATFORM_LINUX)
    include(CheckSymbolExists)
    CHECK_SYMBOL_EXISTS(major "sys/mkdev.h" MAJOR_IN_MKDEV)
    CHECK_SYMBOL_EXISTS(major "sys/sysmacros.h" MAJOR_IN_SYSMACROS) 
    if(MAJOR_IN_MKDEV)
      target_compile_definitions(thirdparty_librpm PRIVATE
        MAJOR_IN_MKDEV=1
      )
    endif()
    if(MAJOR_IN_SYSMACROS)
      target_compile_definitions(thirdparty_librpm PRIVATE
        MAJOR_IN_SYSMACROS=1
      )
    endif()
  endif()

  target_link_libraries(thirdparty_librpm PUBLIC
    thirdparty_sqlite
    thirdparty_openssl
    thirdparty_zlib
    thirdparty_libmagic
    thirdparty_popt
    thirdparty_lzma
    thirdparty_zstd
  )

  target_link_libraries(thirdparty_librpm PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_librpm PRIVATE
    "${library_root}"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/${TARGET_PROCESSOR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}"
    "${library_root}/include"
  )

  target_include_directories(thirdparty_librpm SYSTEM INTERFACE
    "${library_root}/include"
  )
endfunction()

librpmMain()
