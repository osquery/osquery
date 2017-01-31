/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/regex.hpp>
#include <boost/xpressive/xpressive.hpp>

// This must come after the boost expressive headers.
#include <IOKit/kext/KextManager.h>

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/events/kernel.h"

namespace xp = boost::xpressive;

namespace osquery {

DECLARE_bool(disable_kernel);

static const CFStringRef kKernelBundleId =
    CFSTR("com.facebook.security.osquery");
static const CFStringRef kKernelExtensionDirectory =
    CFSTR("/Library/Extensions/");
static const std::string kKernelBundleRegex =
    ".*Kernel Extensions in "
    "backtrace:.*com\\.facebook\\.security\\.osquery.*Kernel version:";
static const std::string kBlockingFile = "/var/osquery/.gtfo";
static const std::string kKernelPackageReceipt =
    "/private/var/db/receipts/com.facebook.osquery.kernel.plist";

void loadKernelExtension() {
  // Check if the kernel extension package is installed.
  auto results = SQL::selectAllFrom(
      "package_receipts", "path", EQUALS, kKernelPackageReceipt);
  if (results.size() == 0) {
    // The kernel package is not installed.
    return;
  }

  // Find the panic log file for the last panic if we are booting out of panic.
  results =
      SQL::SQL(
          "SELECT f.path AS path FROM (SELECT * FROM nvram WHERE name like "
          "'%panic%') AS nv JOIN (SELECT * FROM file WHERE "
          "directory='/Library/Logs/DiagnosticReports/' AND path like "
          "'%/Kernel%' ORDER BY ctime DESC LIMIT 1) as f;")
          .rows();

  // If a panic exists, check if it was caused by the osquery extension.
  if (results.size() == 1) {
    std::string panic_content;
    if (readFile(results[0]["path"], panic_content).ok()) {
      auto rx = xp::sregex::compile(kKernelBundleRegex);
      xp::smatch matches;
      // If so, write a blacklist file that prevents future load attempts.
      if (xp::regex_search(panic_content, matches, rx)) {
        LOG(ERROR) << "Panic was caused by osquery kernel extension";
        writeTextFile(kBlockingFile, "");
      }
    }
  }

  // Check if the kernel extension is manually (or set from crash) blocked.
  results = SQL::selectAllFrom("file", "path", EQUALS, kBlockingFile);
  if (FLAGS_disable_kernel) {
    LOG(INFO) << "Kernel extension is disabled";
    return;
  } else if (results.size() > 0) {
    LOG(WARNING) << "Kernel extension disabled by file";
    return;
  }

  CFURLRef urls[1];
  CFArrayRef directoryArray;

  urls[0] = CFURLCreateWithString(nullptr, kKernelExtensionDirectory, nullptr);

  directoryArray =
      CFArrayCreate(nullptr, (const void**)urls, 1, &kCFTypeArrayCallBacks);
  if (KextManagerLoadKextWithIdentifier(kKernelBundleId, directoryArray) !=
      kOSReturnSuccess) {
    VLOG(1) << "Could not autoload kernel extension";
  } else {
    VLOG(1) << "Autoloaded osquery kernel extension";
  }
  CFRelease(directoryArray);
}

} // namespace osquery
