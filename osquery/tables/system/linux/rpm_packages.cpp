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

#include <memory>
#include <type_traits>

#include <unistd.h>

#include <boost/noncopyable.hpp>
#include <boost/optional.hpp>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/mutex.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

// librpm may be configured and compiled with glibc < 2.17.
#if defined(__GLIBC__) && __GLIBC_MINOR__ >= 17
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
      result = SQL_TEXT(attr);
    }
  }

  return result;
}

// Serializes and owns librpm's non-thread-safe process-global state:
// RPM_CONFIGDIR, the rpmlog callback, crypto, and rc. Model:
//
//   - Callers take lock() and then construct a session. Lock and construction
//     are separate so the forked namespace worker can construct without the
//     lock (see below).
//   - depth_ counts nested sessions. Only the outermost (depth 0) sets up and,
//     on teardown, frees the global state; nested sessions reuse it. Freeing or
//     reinstalling the callback under a live outer-scan iterator corrupts it.
//   - A same-thread join nests: rpm_package_files holds the lock across yield()
//     while SQLite drives an inner rpm_packages scan on the same thread. Hence
//     the recursive mutex (re-lock instead of self-deadlock) and the reuse.
//   - The namespace worker forks with the mutex held by the parent, so the
//     child must not lock (it inherited a copy owned by an absent thread) and
//     re-inits its own session; owner_pid_ sees the new pid and resets.
//   - State is plain static, not thread_local: all in-process access is under
//     mutex_, and the only unlocked accessor -- the single-threaded child --
//     needs no per-thread storage or atomics.
//   - The rpmlog callback's data pointer, installed by the depth-0 session, is
//     read by every nested session's notices, so it must outlive the deepest
//     one. An outer generator can force-unwind (early LIMIT / short-circuited
//     join) before a nested session ends, freeing a coroutine-stack logger
//     while depth_ is still nonzero. So in-process callers pass the
//     process-lifetime GLOGLogger::instance(); the fork-isolated worker passes
//     its own IPC logger.
class RpmSession : public boost::noncopyable {
 public:
  [[nodiscard]] static RecursiveLock lock() {
    return RecursiveLock(mutex_);
  }

  explicit RpmSession(Logger& logger) {
    if (depth_ != 0 && owner_pid_ != getpid()) {
      depth_ = 0;
    }

    if (depth_ == 0) {
      owner_pid_ = getpid();

      prev_config_ = getEnvVar("RPM_CONFIGDIR");
      if (!prev_config_.is_initialized()) {
        setEnvVar("RPM_CONFIGDIR", "/usr/lib/rpm");
      }

      prev_callback_ = rpmlogSetCallback(&RpmSession::Callback, &logger);
      rpmInitCrypto();
      ok_ = rpmReadConfigFiles(nullptr, nullptr) == 0;
    }

    // After setup: a throw above must not strand depth_ (no dtor would run).
    ++depth_;
  }

  ~RpmSession() {
    if (--depth_ == 0) {
      rpmFreeCrypto();
      rpmFreeRpmrc();

      if (prev_callback_ != nullptr) {
        // The previous data pointer is unrecoverable, but the scan is done.
        rpmlogSetCallback(prev_callback_, nullptr);
        prev_callback_ = nullptr;
      }

      if (!prev_config_.is_initialized()) {
        unsetEnvVar("RPM_CONFIGDIR");
      }
      prev_config_ = boost::none;

      ok_ = false;
    }
  }

  bool ok() const {
    return ok_;
  }

  // Invoked by librpm across a C boundary, where an escaping throw is UB.
  static int Callback(rpmlogRec rec, rpmlogCallbackData data) noexcept {
    static std::string last_message;

    Logger* logger = reinterpret_cast<Logger*>(data);

    try {
      if (rpmlogRecMessage(rec) != nullptr) {
        if (last_message != rpmlogRecMessage(rec)) {
          last_message = rpmlogRecMessage(rec);
          logger->vlog(1, "RPM notice: " + last_message);
        }
      }
    } catch (const std::exception&) {
    }
    return 0;
  }

 private:
  static RecursiveMutex mutex_;
  static unsigned depth_;
  static pid_t owner_pid_;
  static bool ok_;
  static rpmlogCallback prev_callback_;
  static boost::optional<std::string> prev_config_;
};

RecursiveMutex RpmSession::mutex_;
unsigned RpmSession::depth_ = 0;
pid_t RpmSession::owner_pid_ = 0;
bool RpmSession::ok_ = false;
rpmlogCallback RpmSession::prev_callback_ = nullptr;
boost::optional<std::string> RpmSession::prev_config_;

// Core rpm_packages scan. Privileges must already be dropped by the caller; see
// genRpmPackagesImpl (namespace worker) and genRpmPackages (direct path).
static QueryData genRpmPackagesCore(QueryContext& context, Logger& logger) {
  QueryData results;

  // The following implementation uses http://rpm.org/api/4.11.1/
  RpmSession rpm_session(logger);
  if (!rpm_session.ok()) {
    logger.vlog(1, "Cannot read RPM configuration files");
    return results;
  }

  rpmts ts = rpmtsCreate();

  auto emitPackage = [&](Header header) {
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
  };

  auto scan = [&](rpmdbMatchIterator matches) {
    Header header;
    while ((header = rpmdbNextIterator(matches)) != nullptr) {
      emitPackage(header);
    }
    rpmdbFreeIterator(matches);
  };

  // The name column is `optimized`, so SQLite hands us the whole IN list in
  // this one call. Do an indexed Name lookup per value -- librpm reads only the
  // matching headers -- rather than iterating the whole database and filtering
  // each header by string compare.
  if (context.constraints["name"].exists(EQUALS)) {
    for (const auto& name : context.constraints["name"].getAll(EQUALS)) {
      scan(rpmtsInitIterator(ts, RPMTAG_NAME, name.c_str(), name.size()));
    }
  } else {
    scan(rpmtsInitIterator(ts, RPMTAG_NAME, nullptr, 0));
  }

  rpmtsFree(ts);

  return results;
}

// Namespace-worker entry point. generateInNamespace takes a plain function
// pointer (so this can't be a lambda): the forked child keeps privileges to
// enter the namespace, then drops here before touching the rpmdb.
QueryData genRpmPackagesImpl(QueryContext& context, Logger& logger) {
  auto dropper = DropPrivileges::get();
  if (!dropper->dropTo("nobody") && isUserAdmin()) {
    logger.log(google::GLOG_WARNING, "Cannot drop privileges for rpm_packages");
    return {};
  }

  return genRpmPackagesCore(context, logger);
}

QueryData genRpmPackages(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    // Lock in the parent, not the worker: the child would inherit it locked by
    // an absent thread. The worker keeps privileges to enter the namespace and
    // drops inside genRpmPackagesImpl.
    auto rpm_lock = RpmSession::lock();
    return generateInNamespace(context, "rpm_packages", genRpmPackagesImpl);
  }

  // Drop before locking (mirrors genRpmPackageFiles) so the drop's `users`
  // sub-query does not run inside the global rpm critical section.
  auto& logger = GLOGLogger::instance();
  auto dropper = DropPrivileges::get();
  if (!dropper->dropTo("nobody") && isUserAdmin()) {
    logger.log(google::GLOG_WARNING, "Cannot drop privileges for rpm_packages");
    return {};
  }

  auto rpm_lock = RpmSession::lock();
  return genRpmPackagesCore(context, logger);
}

namespace {

// librpm C handles owned via RAII. genRpmPackageFiles yields inside its loops;
// boost.coroutine2 forced-unwind on early query termination (LIMIT, a
// short-circuited join) runs only local destructors, so frees placed after the
// loops would be skipped and leak. Ownership by unique_ptr frees them on every
// exit, including that unwind.
struct RpmtsDeleter {
  void operator()(rpmts ts) const noexcept {
    rpmtsFree(ts);
  }
};
struct RpmdbIteratorDeleter {
  void operator()(rpmdbMatchIterator mi) const noexcept {
    rpmdbFreeIterator(mi);
  }
};
struct RpmfiDeleter {
  void operator()(rpmfi fi) const noexcept {
    rpmfiFree(fi);
  }
};
struct RpmtdDeleter {
  void operator()(rpmtd td) const noexcept {
    rpmtdFree(td);
  }
};

using RpmtsPtr = std::unique_ptr<std::remove_pointer_t<rpmts>, RpmtsDeleter>;
using RpmdbIteratorPtr =
    std::unique_ptr<std::remove_pointer_t<rpmdbMatchIterator>,
                    RpmdbIteratorDeleter>;
using RpmfiPtr = std::unique_ptr<std::remove_pointer_t<rpmfi>, RpmfiDeleter>;
using RpmtdPtr = std::unique_ptr<std::remove_pointer_t<rpmtd>, RpmtdDeleter>;

} // namespace

void genRpmPackageFiles(RowYield& yield, QueryContext& context) {
  auto& logger = GLOGLogger::instance();
  auto dropper = DropPrivileges::get();
  if (!dropper->dropTo("nobody") && isUserAdmin()) {
    logger.log(google::GLOG_WARNING,
               "Cannot drop privileges for rpm_packages_files");
    return;
  }

  auto rpm_lock = RpmSession::lock();

  RpmSession rpm_session(logger);
  if (!rpm_session.ok()) {
    logger.vlog(1, "Cannot read RPM configuration files");
    return;
  }

  RpmtsPtr ts(rpmtsCreate());

  auto emitFiles = [&](Header header) {
    RpmtdPtr td(rpmtdNew());
    RpmfiPtr fi(rpmfiNew(ts.get(), header, RPMTAG_BASENAMES, RPMFI_NOHEADER));
    std::string package_name =
        getRpmAttribute(header, RPMTAG_NAME, td.get(), logger);

    auto file_count = rpmfiFC(fi.get());
    if (file_count <= 0) {
      logger.vlog(1, "RPM package " + package_name + " contains 0 files");
      return;
    } else if (file_count > MAX_RPM_FILES) {
      logger.vlog(1,
                  "RPM package " + package_name + " contains over " +
                      std::to_string(MAX_RPM_FILES) + " files");
      return;
    }

    // Iterate over every file in this package.
    for (size_t i = 0; rpmfiNext(fi.get()) >= 0 && i < file_count; i++) {
      auto r = make_table_row();
      auto path = rpmfiFN(fi.get());
      r["package"] = package_name;
      r["path"] = (path != nullptr) ? path : "";
      auto username = rpmfiFUser(fi.get());
      r["username"] = (username != nullptr) ? username : "";
      auto groupname = rpmfiFGroup(fi.get());
      r["groupname"] = (groupname != nullptr) ? groupname : "";
      r["mode"] = lsperms(rpmfiFMode(fi.get()));
      r["size"] = BIGINT(rpmfiFSize(fi.get()));

      int digest_algo;
      auto digest = rpmfiFDigestHex(fi.get(), &digest_algo);
      if (digest_algo == PGPHASHALGO_SHA256) {
        r["sha256"] = (digest != nullptr) ? digest : "";
      }
      if (digest != nullptr) {
        free(digest);
      }

      yield(std::move(r));
    }
  };

  auto scan = [&](RpmdbIteratorPtr matches) {
    Header header;
    while ((header = rpmdbNextIterator(matches.get())) != nullptr) {
      emitFiles(header);
    }
  };

  // The package column is `optimized`, so SQLite hands us the whole IN list in
  // this one call. Do an indexed Name lookup per value -- librpm reads only the
  // matching headers -- rather than iterating the whole database and filtering
  // each header by string compare.
  if (context.constraints["package"].exists(EQUALS)) {
    for (const auto& package : context.constraints["package"].getAll(EQUALS)) {
      scan(RpmdbIteratorPtr(rpmtsInitIterator(
          ts.get(), RPMTAG_NAME, package.c_str(), package.size())));
    }
  } else {
    scan(
        RpmdbIteratorPtr(rpmtsInitIterator(ts.get(), RPMTAG_NAME, nullptr, 0)));
  }
}
} // namespace tables
} // namespace osquery
