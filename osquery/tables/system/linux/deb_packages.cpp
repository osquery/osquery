// Copyright 2004-present Facebook. All Rights Reserved.

#include <ctime>

#include <stdio.h>
#include <stdlib.h>

#include <fnmatch.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// see README.api of libdpkg-dev
#define LIBDPKG_VOLATILE_API

extern "C" {
#include <dpkg/dpkg-db.h>
/*
typedef pkginfo::pkgwant pkgwant;
typedef pkginfo::pkgeflag pkgflag;
typedef pkginfo::pkgstatus pkgstatus;
*/

// copy pasted from dpkg-db.h
enum pkgwant {
  want_unknown, want_install, want_hold, want_deinstall, want_purge,
  /** Not allowed except as special sentinel value in some places. */
  want_sentinel,
} want;
/** The error flag bitmask. */
enum pkgeflag {
  eflag_ok		= 0,
  eflag_reinstreq	= 1,
} eflag;
enum pkgstatus {
  stat_notinstalled,
  stat_configfiles,
  stat_halfinstalled,
  stat_unpacked,
  stat_halfconfigured,
  stat_triggersawaited,
  stat_triggerspending,
  stat_installed
} status;

#include <dpkg/dpkg.h>

#include <dpkg/pkg-array.h>
#include <dpkg/pkg-format.h>
#include <dpkg/pkg-show.h>
#include <dpkg/string.h>
#include <dpkg/path.h>

}


#include <boost/lexical_cast.hpp>

#include "osquery/database.h"

namespace osquery {
namespace tables {

QueryData genDebs() {
  QueryData results;


    struct pkg_array array;
    struct pkginfo *pkg;
    int i;
    LOG(ERROR) <<  "AAAAA";
    dpkg_program_init("dpkg");
    LOG(ERROR) <<  "AAAAA";
    modstatdb_open(msdbrw_readonly);
    LOG(ERROR) <<  "AAAAA";
    pkg_array_init_from_db(&array);
    LOG(ERROR) <<  "AAAAA";
    pkg_array_sort(&array, pkg_sorter_by_nonambig_name_arch);
    LOG(ERROR) <<  "AAAAA";

    for (i = 0; i < array.n_pkgs; i++) {
      pkg = array.pkgs[i];

      if (pkg->status == pkg->stat_notinstalled) continue;
      Row r;
      r["name"] = pkg_name(pkg, pnaw_nonambig);
      r["version"] = versiondescribe(&pkg->installed.version, vdew_nonambig);
      r["arch"] =  dpkg_arch_describe(pkg->installed.arch);
      /*
      LOG(ERROR) << pkg_abbrev_want(pkg);
      LOG(ERROR) << pkg_abbrev_status(pkg);
    		  LOG(ERROR) << pkg_abbrev_eflag(pkg);
    		  LOG(ERROR) << pkg_name(pkg, pnaw_nonambig);
    		  LOG(ERROR) << versiondescribe(&pkg->installed.version, vdew_nonambig);
    		  LOG(ERROR) << dpkg_arch_describe(pkg->installed.arch);
    		  */
      results.push_back(r);
    }

  return results;
}
}
}
