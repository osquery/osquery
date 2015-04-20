/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <ctime>

#include <stdio.h>
#include <stdlib.h>

#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>

#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

/**
 * @brief Return a string representation of the RPM tag type.
 *
 * @param header A librpm header.
 * @param tag A librpm rpmTag_t name.
 * @param td A librpm rpmtd.
 *
 * Given a librpm iterator header and a requested tag name:
 * 1. Determine the type of the tag (the class of value).
 * 2. Request a const pointer or cast of numerate to that class.
 * 3. Lexical-cast the value for SQL.
 *
 * @return The string representation of the tag type.
 */
std::string getRpmAttribute(const Header& header, rpmTag tag, const rpmtd& td) {
  std::string result;

  if (headerGet(header, tag, td, HEADERGET_DEFAULT) == 0) {
    // Intentional check for a 0 = failure.
    VLOG(3) << "Could not get RPM header flag.";
    return result;
  }

  if (rpmTagGetClass(tag) == RPM_NUMERIC_CLASS) {
    long long int attr = rpmtdGetNumber(td);
    result = BIGINT(attr);
  } else if (rpmTagGetClass(tag) == RPM_STRING_CLASS) {
    const char* attr = rpmtdGetString(td);
    if (attr != nullptr) {
      result = TEXT(attr);
    }
  }

  return result;
}

QueryData genRpms(QueryContext& context) {
  QueryData results;

  // The following implementation uses http://rpm.org/api/4.11.1/
  Header header;
  rpmdbMatchIterator match_iterator;

  rpmInitCrypto();
  if (rpmReadConfigFiles(nullptr, nullptr) != 0) {
    LOG(ERROR) << "Cannot read RPM configuration files.";
    return results;
  }

  rpmts ts = rpmtsCreate();
  match_iterator = rpmtsInitIterator(ts, RPMTAG_NAME, nullptr, 0);
  while ((header = rpmdbNextIterator(match_iterator)) != nullptr) {
    Row r;
    rpmtd td = rpmtdNew();
    r["name"] = getRpmAttribute(header, RPMTAG_NAME, td);
    r["version"] = getRpmAttribute(header, RPMTAG_VERSION, td);
    r["release"] = getRpmAttribute(header, RPMTAG_RELEASE, td);
    r["source"] = getRpmAttribute(header, RPMTAG_SOURCERPM, td);
    r["size"] = getRpmAttribute(header, RPMTAG_SIZE, td);
    r["sha1"] = getRpmAttribute(header, RPMTAG_SHA1HEADER, td);
    r["arch"] = getRpmAttribute(header, RPMTAG_ARCH, td);

    rpmtdFree(td);
    results.push_back(r);
  }

  rpmdbFreeIterator(match_iterator);
  rpmtsFree(ts);

  rpmFreeCrypto();
  rpmFreeRpmrc();

  return results;
}
}
}