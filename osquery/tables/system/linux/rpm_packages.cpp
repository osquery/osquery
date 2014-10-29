// Copyright 2004-present Facebook. All Rights Reserved.

#include <ctime>
#include <boost/lexical_cast.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include "osquery/database.h"

using std::string;
using boost::lexical_cast;

namespace osquery {
namespace tables {

QueryData genRpms() {
  rpmts ts = NULL;
  Header h;
  rpmdbMatchIterator mi;
  QueryData results;
  char *n, *v, *r, *g, *a;
  ts = rpmtsCreate();
  rpmReadConfigFiles( NULL, NULL );
  mi = rpmtsInitIterator( ts, RPMTAG_NAME, NULL, 0);
  while (NULL != (h = rpmdbNextIterator(mi))) {
    Row r;
    rpmtd td = rpmtdNew();
    headerGet( h, RPMTAG_NAME, td, HEADERGET_DEFAULT);
    const char* rpm_name = rpmtdGetString(td);
    headerGet( h, RPMTAG_VERSION, td, HEADERGET_DEFAULT);
    const char* rpm_version = rpmtdGetString(td);
    headerGet( h, RPMTAG_RELEASE, td, HEADERGET_DEFAULT);
    const char* rpm_release = rpmtdGetString(td);
    headerGet( h, RPMTAG_SOURCERPM, td, HEADERGET_DEFAULT);
    const char* rpm_sourcerpm = rpmtdGetString(td);
    headerGet( h, RPMTAG_SIZE, td, HEADERGET_DEFAULT);
    const char* rpm_size = rpmtdGetString(td);
    headerGet( h, RPMTAG_DSAHEADER , td, HEADERGET_DEFAULT);
    const char* rpm_dsaheader = rpmtdGetString(td);
    headerGet( h, RPMTAG_RSAHEADER , td, HEADERGET_DEFAULT);
    const char* rpm_rsaheader = rpmtdGetString(td);
    headerGet( h, RPMTAG_SHA1HEADER , td, HEADERGET_DEFAULT);
    const char* rpm_sha1header = rpmtdGetString(td);
    headerGet( h, RPMTAG_ARCH, td, HEADERGET_DEFAULT);
    const char* rpm_arch = rpmtdGetString(td);
    if (!rpm_name) {
        rpm_name="";
    }
    if (!rpm_version) {
        rpm_version="";
    }
    if (!rpm_release) {
        rpm_release="";
    }
    if (!rpm_sourcerpm) {
        rpm_sourcerpm="";
    }
    if (!rpm_size) {
        rpm_size="";
    }
    if (!rpm_dsaheader) {
        rpm_dsaheader="";
    }
    if (!rpm_rsaheader) {
        rpm_rsaheader="";
    }
    if (!rpm_sha1header) {
        rpm_sha1header="";
    }
    if (!rpm_arch) {
        rpm_arch="";
    }

    r["name"] = std::string(rpm_name);
    r["version"] = std::string(rpm_version);
    r["release"] = std::string(rpm_release);
    r["source"] = std::string(rpm_sourcerpm);
    r["size"] = std::string(rpm_size);
    r["dsaheader"] = std::string(rpm_dsaheader);
    r["rsaheader"] = std::string(rpm_rsaheader);
    r["sha1header"] = std::string(rpm_sha1header);
    r["arch"] = std::string(rpm_arch);
    results.push_back(r);
  }

  rpmdbFreeIterator(mi);
  rpmtsFree(ts);
  return results;
}
}
}