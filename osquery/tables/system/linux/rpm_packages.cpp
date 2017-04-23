/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <rpm/header.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmts.h>

#include <boost/noncopyable.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/process.h"

namespace osquery {
namespace tables {

// Maximum number of files per RPM.
#define MAX_RPM_FILES 2048

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
static std::string getRpmAttribute(const Header& header,
                                   rpmTag tag,
                                   const rpmtd& td) {
  std::string result;
  if (headerGet(header, tag, td, HEADERGET_DEFAULT) == 0) {
    // Intentional check for a 0 = failure.
    TLOG << "Could not get RPM header flag.";
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

class RpmEnvironmentManager : public boost::noncopyable {
 public:
  RpmEnvironmentManager() : config_(getEnvVar("RPM_CONFIGDIR")) {
    // Honor a caller's environment
    if (!config_.is_initialized()) {
      setEnvVar("RPM_CONFIGDIR", "/usr/lib/rpm");
    }

    callback_ = rpmlogSetCallback(&RpmEnvironmentManager::Callback, nullptr);
  }

  ~RpmEnvironmentManager() {
    // If we had set the environment, clean it up afterward.
    if (!config_.is_initialized()) {
      unsetEnvVar("RPM_CONFIGDIR");
    }

    if (callback_ != nullptr) {
      rpmlogSetCallback(callback_, nullptr);
      callback_ = nullptr;
    }
  }

  static int Callback(rpmlogRec rec, rpmlogCallbackData) {
    static std::string last_message;

    if (rpmlogRecMessage(rec) != nullptr) {
      if (last_message != rpmlogRecMessage(rec)) {
        last_message = rpmlogRecMessage(rec);
        VLOG(1) << "RPM notice: " << last_message;
      }
    }
    return 0;
  }

 private:
  // Previous configuration directory.
  boost::optional<std::string> config_;

  // Previous callback function.
  rpmlogCallback callback_{nullptr};
};

QueryData genRpmPackages(QueryContext& context) {
  QueryData results;

  auto dropper = DropPrivileges::get();
  if (!dropper->dropTo("nobody") && isUserAdmin()) {
    LOG(WARNING) << "Cannot drop privileges for rpm_packages";
    return results;
  }

  // Isolate RPM/package inspection to the canonical: /usr/lib/rpm.
  RpmEnvironmentManager env_manager;

  // The following implementation uses http://rpm.org/api/4.11.1/
  rpmInitCrypto();
  if (rpmReadConfigFiles(nullptr, nullptr) != 0) {
    TLOG << "Cannot read RPM configuration files";
    return results;
  }

  rpmts ts = rpmtsCreate();
  rpmdbMatchIterator matches;
  if (context.constraints["name"].exists(EQUALS)) {
    auto name = (*context.constraints["name"].getAll(EQUALS).begin());
    matches = rpmtsInitIterator(ts, RPMTAG_NAME, name.c_str(), name.size());
  } else {
    matches = rpmtsInitIterator(ts, RPMTAG_NAME, nullptr, 0);
  }

  Header header;
  while ((header = rpmdbNextIterator(matches)) != nullptr) {
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

  rpmdbFreeIterator(matches);
  rpmtsFree(ts);
  rpmFreeCrypto();
  rpmFreeRpmrc();

  return results;
}

QueryData genRpmPackageFiles(QueryContext& context) {
  QueryData results;

  auto dropper = DropPrivileges::get();
  if (!dropper->dropTo("nobody") && isUserAdmin()) {
    LOG(WARNING) << "Cannot drop privileges for rpm_package_files";
    return results;
  }

  // Isolate RPM/package inspection to the canonical: /usr/lib/rpm.
  RpmEnvironmentManager env_manager;

  if (rpmReadConfigFiles(nullptr, nullptr) != 0) {
    TLOG << "Cannot read RPM configuration files";
    return results;
  }

  rpmts ts = rpmtsCreate();
  rpmdbMatchIterator matches;
  if (context.constraints["package"].exists(EQUALS)) {
    auto name = (*context.constraints["package"].getAll(EQUALS).begin());
    matches = rpmtsInitIterator(ts, RPMTAG_NAME, name.c_str(), name.size());
  } else {
    matches = rpmtsInitIterator(ts, RPMTAG_NAME, nullptr, 0);
  }

  Header header;
  while ((header = rpmdbNextIterator(matches)) != nullptr) {
    rpmtd td = rpmtdNew();
    rpmfi fi = rpmfiNew(ts, header, RPMTAG_BASENAMES, RPMFI_NOHEADER);
    auto file_count = rpmfiFC(fi);
    if (file_count <= 0 || file_count > MAX_RPM_FILES) {
      // This package contains no or too many files.
      rpmfiFree(fi);
      continue;
    }

    // Iterate over every file in this package.
    for (size_t i = 0; rpmfiNext(fi) >= 0 && i < file_count; i++) {
      Row r;
      r["package"] = getRpmAttribute(header, RPMTAG_NAME, td);
      auto path = rpmfiFN(fi);
      r["path"] = (path != nullptr) ? path : "";
      auto username = rpmfiFUser(fi);
      r["username"] = (username != nullptr) ? username : "";
      auto groupname = rpmfiFGroup(fi);
      r["groupname"] = (groupname != nullptr) ? groupname : "";
      r["mode"] = lsperms(rpmfiFMode(fi));
      r["size"] = BIGINT(rpmfiFSize(fi));

      int digest_algo;
      auto digest = rpmfiFDigestHex(fi, &digest_algo);
      if (digest_algo == PGPHASHALGO_SHA256) {
        r["sha256"] = (digest != nullptr) ? digest : "";
      }

      results.push_back(r);
    }

    rpmfiFree(fi);
    rpmtdFree(td);
  }

  rpmdbFreeIterator(matches);
  rpmtsFree(ts);
  rpmFreeRpmrc();

  return results;
}
}
}
