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
  rpmdbIndexIterator mi;
  QueryData results;
  char *n, *v, *r, *g, *a;
  ts = rpmtsCreate();
  rpmReadConfigFiles( NULL, NULL );
  mi = rpmtsInitIterator( ts, RPMDBI_PACKAGES, NULL, 0);
  while (NULL != (h = rpmdbNextIterator(mi))) {
    Row r;
    h = headerLink( h );
    headerGetEntry( h, RPMTAG_NAME, NULL, (void**)&n, NULL);
    headerGetEntry( h, RPMTAG_VERSION, NULL, (void**)&v, NULL);
    headerGetEntry( h, RPMTAG_RELEASE, NULL, (void**)&r, NULL);
    headerGetEntry( h, RPMTAG_GROUP, NULL, (void**)&g, NULL);
    headerGetEntry( h, RPMTAG_ARCH, NULL, (void**)&a, NULL);
    r["name"] = lexical_cast<string>(now->n);
    r["version"] = lexical_cast<string>(now->v);
    r["release"] = lexical_cast<string>(now->r);
    r["group"] = lexical_cast<string>(now->g);
    r["arch"] = lexical_cast<string>(now->a);
    results.push_back(r);
  }
  rpmdbFreeIterator(mi);
  rpmtsFree(ts);
  return results;
}
}
}