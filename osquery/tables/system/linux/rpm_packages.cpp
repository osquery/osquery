// Copyright 2004-present Facebook. All Rights Reserved.

#include <ctime>

#include <stdio.h>
#include <stdlib.h>

#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>

#include <boost/lexical_cast.hpp>

#include "osquery/database.h"

namespace osquery {
namespace tables {

QueryData genRpms() {
  QueryData results;

  Header header;
  rpmdbMatchIterator match_iterator;
  rpmReadConfigFiles(NULL, NULL);

  rpmts ts = rpmtsCreate();
  match_iterator = rpmtsInitIterator(ts, RPMTAG_NAME, NULL, 0);
  while ((header = rpmdbNextIterator(match_iterator)) != NULL) {
    Row r;
    rpmtd td = rpmtdNew();

    headerGet(header, RPMTAG_NAME, td, HEADERGET_DEFAULT);
    r["name"] = std::string(rpmtdGetString(td));

    headerGet(header, RPMTAG_VERSION, td, HEADERGET_DEFAULT);
    r["version"] = std::string(rpmtdGetString(td));

    headerGet(header, RPMTAG_RELEASE, td, HEADERGET_DEFAULT);
    r["release"] = std::string(rpmtdGetString(td));

    headerGet(header, RPMTAG_SOURCERPM, td, HEADERGET_DEFAULT);
    r["source"] = std::string(rpmtdGetString(td));

    headerGet(header, RPMTAG_SIZE, td, HEADERGET_DEFAULT);
    r["size"] = std::string(rpmtdGetString(td));

    headerGet(header, RPMTAG_DSAHEADER, td, HEADERGET_DEFAULT);
    r["dsaheader"] = std::string(rpmtdGetString(td));

    headerGet(header, RPMTAG_RSAHEADER, td, HEADERGET_DEFAULT);
    r["rsaheader"] = std::string(rpmtdGetString(td));

    headerGet(header, RPMTAG_SHA1HEADER, td, HEADERGET_DEFAULT);
    r["sha1header"] = std::string(rpmtdGetString(td));

    headerGet(header, RPMTAG_ARCH, td, HEADERGET_DEFAULT);
    r["arch"] = std::string(rpmtdGetString(td));

    results.push_back(r);
  }

  rpmdbFreeIterator(match_iterator);
  rpmtsFree(ts);
  return results;
}
}
}