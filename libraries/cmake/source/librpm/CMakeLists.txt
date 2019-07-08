# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(librpmMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_librpm
    "${library_root}/rpmio/argv.c"
    "${library_root}/build/build.c"
    "${library_root}/cliutils.c"
    "${library_root}/lib/cpio.c"
    "${library_root}/lib/backend/db3.c"
    "${library_root}/lib/backend/dbi.c"
    "${library_root}/lib/backend/dbiset.c"
    "${library_root}/lib/depends.c"
    "${library_root}/rpmio/digest.c"
    "${library_root}/rpmio/digest_openssl.c"
    "${library_root}/build/expression.c"
    "${library_root}/build/files.c"
    "${library_root}/misc/fnmatch.c"
    "${library_root}/lib/formats.c"
    "${library_root}/lib/fprint.c"
    "${library_root}/lib/fsm.c"
    "${library_root}/misc/fts.c"
    "${library_root}/lib/header.c"
    "${library_root}/lib/headerfmt.c"
    "${library_root}/lib/headerutil.c"
    "${library_root}/rpmio/macro.c"
    "${library_root}/lib/manifest.c"
    "${library_root}/build/misc.c"
    "${library_root}/lib/order.c"
    "${library_root}/lib/package.c"
    "${library_root}/build/pack.c"
    "${library_root}/build/parseBuildInstallClean.c"
    "${library_root}/build/parseChangelog.c"
    "${library_root}/build/parseDescription.c"
    "${library_root}/build/parseFiles.c"
    "${library_root}/build/parsePolicies.c"
    "${library_root}/build/parsePreamble.c"
    "${library_root}/build/parsePrep.c"
    "${library_root}/build/parseReqs.c"
    "${library_root}/build/parseScript.c"
    "${library_root}/build/parseSpec.c"
    "${library_root}/build/policies.c"
    "${library_root}/lib/poptI.c"
    "${library_root}/lib/poptQV.c"
    "${library_root}/lib/psm.c"
    "${library_root}/lib/query.c"
    "${library_root}/lib/relocation.c"
    "${library_root}/build/reqprov.c"
    "${library_root}/lib/rpmal.c"
    "${library_root}/lib/rpmchecksig.c"
    "${library_root}/lib/rpmchroot.c"
    "${library_root}/lib/rpmdb.c"
    "${library_root}/lib/rpmds.c"
    "${library_root}/build/rpmfc.c"
    "${library_root}/lib/rpmfi.c"
    "${library_root}/rpmio/rpmfileutil.c"
    "${library_root}/lib/rpmfs.c"
    "${library_root}/sign/rpmgensig.c"
    "${library_root}/lib/rpmgi.c"
    "${library_root}/rpmio/rpmglob.c"
    "${library_root}/rpmio/rpmhook.c"
    "${library_root}/lib/rpminstall.c"
    "${library_root}/rpmio/rpmio.c"
    "${library_root}/rpmio/rpmkeyring.c"
    "${library_root}/lib/rpmlead.c"
    "${library_root}/lib/rpmlock.c"
    "${library_root}/rpmio/rpmlog.c"
    "${library_root}/rpmio/rpmmalloc.c"
    "${library_root}/rpmio/rpmpgp.c"
    "${library_root}/lib/rpmplugins.c"
    "${library_root}/lib/rpmprob.c"
    "${library_root}/lib/rpmps.c"
    "${library_root}/lib/rpmrc.c"
    "${library_root}/lib/rpmscript.c"
    "${library_root}/rpmio/rpmsq.c"
    "${library_root}/rpmio/rpmstring.c"
    "${library_root}/rpmio/rpmstrpool.c"
    "${library_root}/rpmio/rpmsw.c"
    "${library_root}/lib/rpmtd.c"
    "${library_root}/lib/rpmte.c"
    "${library_root}/lib/rpmtriggers.c"
    "${library_root}/lib/rpmts.c"
    "${library_root}/lib/rpmug.c"
    "${library_root}/lib/rpmvercmp.c"
    "${library_root}/lib/rpmvs.c"
    "${library_root}/lib/signature.c"
    "${library_root}/build/spec.c"
    "${library_root}/lib/tagexts.c"
    "${library_root}/lib/tagname.c"
    "${library_root}/lib/transaction.c"
    "${library_root}/rpmio/url.c"
    "${library_root}/lib/verify.c"
    "${library_root}/rpmio/base64.c"
    "${library_root}/lib/poptALL.c"
  )

  target_compile_definitions(thirdparty_librpm PRIVATE
    EVP_md2=EVP_md_null
    HAVE_CONFIG_H
    IAM_RPMEIU
    IAM_RPMQ
    IAM_RPMV
    LIBRPMALIAS_EXECPATH="\"/usr/local/bin\""
    LIBRPMALIAS_EXECPATH=\"/usr/local/bin\"
    LIBRPMALIAS_FILENAME="\"rpmpopt-4.14.1\""
    LIBRPMALIAS_FILENAME=\"rpmpopt-4.14.1\"
    LOCALEDIR="\"/usr/local/share/locale\""
    LOCALEDIR=\"/usr/local/share/locale\"
    LOCALSTATEDIR="\"/usr/local/var\""
    LOCALSTATEDIR=\"/usr/local/var\"
    PIC
    _REENTRANT
    RPMCONFIGDIR="\"/usr/local/lib/rpm\""
    RPMCONFIGDIR=\"/usr/local/lib/rpm\"
    SYSCONFDIR="\"/usr/local/etc\""
    SYSCONFDIR=\"/usr/local/etc\"
  )

  target_link_libraries(thirdparty_librpm PUBLIC
    thirdparty_berkeley-db
    thirdparty_openssl
    thirdparty_zlib
    thirdparty_libmagic
    thirdparty_popt
  )

  target_link_libraries(thirdparty_librpm PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_librpm PRIVATE
    "${library_root}"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated"
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )

  target_include_directories(thirdparty_librpm SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/generated"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )
endfunction()

librpmMain()
