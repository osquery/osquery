/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <rpm/header.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmts.h>

#include <boost/noncopyable.hpp>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

// librpm may be configured and compiled with glibc < 2.17.
#if defined(__GLIBC__) && __GLIBC_MINOR__ > 17
extern "C" char* __secure_getenv(const char* _s) __attribute__((weak));
extern "C" char* __secure_getenv(const char* _s) {
  return secure_getenv(_s);
}
#endif

namespace osquery {
namespace tables {

// Maximum number of files per RPM.
#define MAX_RPM_FILES (64 * 1024)

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
                                   const rpmtd& td,
                                   Logger& logger) {
  std::string result;
  if (headerGet(header, tag, td, HEADERGET_DEFAULT) == 0) {
    // Intentional check for a 0 = failure.
    logger.vlog(1, "Could not get RPM header flag.");
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
  RpmEnvironmentManager(Logger& logger)
      : config_(getEnvVar("RPM_CONFIGDIR")), logger_(&logger) {
    // Honor a caller's environment
    if (!config_.is_initialized()) {
      setEnvVar("RPM_CONFIGDIR", "/usr/lib/rpm");
    }

    callback_ = rpmlogSetCallback(&RpmEnvironmentManager::Callback, logger_);
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

  static int Callback(rpmlogRec rec, rpmlogCallbackData data) {
    static std::string last_message;

    Logger* logger = reinterpret_cast<Logger*>(data);

    if (rpmlogRecMessage(rec) != nullptr) {
      if (last_message != rpmlogRecMessage(rec)) {
        last_message = rpmlogRecMessage(rec);
        logger->vlog(1, "RPM notice: " + last_message);
      }
    }
    return 0;
  }

 private:
  // Previous configuration directory.
  boost::optional<std::string> config_;

  // Previous callback function.
  rpmlogCallback callback_{nullptr};

  Logger* logger_;
};

QueryData genRpmPackagesImpl(QueryContext& context, Logger& logger) {
  QueryData results;

  auto dropper = DropPrivileges::get();
  if (!dropper->dropTo("nobody") && isUserAdmin()) {
    logger.log(google::GLOG_WARNING, "Cannot drop privileges for rpm_packages");
    return results;
  }

  // Isolate RPM/package inspection to the canonical: /usr/lib/rpm.
  RpmEnvironmentManager env_manager(logger);

  // The following implementation uses http://rpm.org/api/4.11.1/
  rpmInitCrypto();
  if (rpmReadConfigFiles(nullptr, nullptr) != 0) {
    logger.vlog(1, "Cannot read RPM configuration files");
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
    r["name"] = getRpmAttribute(header, RPMTAG_NAME, td, logger);
    r["version"] = getRpmAttribute(header, RPMTAG_VERSION, td, logger);
    r["release"] = getRpmAttribute(header, RPMTAG_RELEASE, td, logger);
    r["source"] = getRpmAttribute(header, RPMTAG_SOURCERPM, td, logger);
    r["size"] = getRpmAttribute(header, RPMTAG_SIZE, td, logger);
    r["sha1"] = getRpmAttribute(header, RPMTAG_SHA1HEADER, td, logger);
    r["arch"] = getRpmAttribute(header, RPMTAG_ARCH, td, logger);
    r["epoch"] = INTEGER(getRpmAttribute(header, RPMTAG_EPOCH, td, logger));
    r["install_time"] =
        INTEGER(getRpmAttribute(header, RPMTAG_INSTALLTIME, td, logger));
    r["vendor"] = getRpmAttribute(header, RPMTAG_VENDOR, td, logger);
    r["package_group"] = getRpmAttribute(header, RPMTAG_GROUP, td, logger);
    r["pid_with_namespace"] = "0";

    rpmtdFree(td);
    results.push_back(r);
  }

  rpmdbFreeIterator(matches);
  rpmtsFree(ts);
  rpmFreeCrypto();
  rpmFreeRpmrc();

  return results;
}

QueryData genRpmPackages(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "rpm_packages", genRpmPackagesImpl);
  } else {
    GLOGLogger logger;
    return genRpmPackagesImpl(context, logger);
  }
}

void genRpmPackageFiles(RowYield& yield, QueryContext& context) {
  GLOGLogger logger;
  auto dropper = DropPrivileges::get();
  if (!dropper->dropTo("nobody") && isUserAdmin()) {
    logger.log(google::GLOG_WARNING,
               "Cannot drop privileges for rpm_packages_files");
    return;
  }

  // Isolate RPM/package inspection to the canonical: /usr/lib/rpm.
  RpmEnvironmentManager env_manager(logger);

  if (rpmReadConfigFiles(nullptr, nullptr) != 0) {
    logger.vlog(1, "Cannot read RPM configuration files");
    return;
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
    std::string package_name = getRpmAttribute(header, RPMTAG_NAME, td, logger);

    auto file_count = rpmfiFC(fi);
    if (file_count <= 0) {
      logger.vlog(1, "RPM package " + package_name + " contains 0 files");
      rpmfiFree(fi);
      rpmtdFree(td);
      continue;
    } else if (file_count > MAX_RPM_FILES) {
      logger.vlog(1,
                  "RPM package " + package_name + " contains over " +
                      std::to_string(MAX_RPM_FILES) + " files");
      rpmfiFree(fi);
      rpmtdFree(td);
      continue;
    }

    // Iterate over every file in this package.
    for (size_t i = 0; rpmfiNext(fi) >= 0 && i < file_count; i++) {
      auto r = make_table_row();
      auto path = rpmfiFN(fi);
      r["package"] = package_name;
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
      if (digest != nullptr) {
        free(digest);
      }

      yield(std::move(r));
    }

    rpmfiFree(fi);
    rpmtdFree(td);
  }

  rpmdbFreeIterator(matches);
  rpmtsFree(ts);
  rpmFreeRpmrc();
}
} // namespace tables
} // namespace osquery
