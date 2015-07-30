/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/events/kernel.h"

#include <boost/regex.hpp>
#include <boost/xpressive/xpressive.hpp>

#include <IOKit/kext/KextManager.h>

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

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

void loadKernelExtension() {
  // Find the panic log file for the last panic if we are just booting out of
  // panic.
  auto results =
      SQL::SQL(
          "SELECT f.path AS path FROM (SELECT * FROM nvram WHERE name like "
          "'%panic%') AS nv JOIN (SELECT * FROM file WHERE "
          "directory='/Library/Logs/DiagnosticReports/' AND path like "
          "'%/Kernel%' ORDER BY ctime DESC LIMIT 1) as f;")
          .rows();

  if (results.size() == 1) {
    std::string panic_content;
    if (readFile(results[0]["path"], panic_content).ok()) {
      auto rx = xp::sregex::compile(kKernelBundleRegex);
      xp::smatch matches;
      if (xp::regex_search(panic_content, matches, rx)) {
        LOG(ERROR) << "Panic was caused by osquery kernel extension.";
        writeTextFile(kBlockingFile, "");
      }
    }
  }

  results =
      SQL::selectAllFrom("file", "path", EQUALS, "/var/osquery/.gtfo");

  if (FLAGS_disable_kernel) {
    LOG(INFO) << "Kernel extension is disabled.";
  } else if (results.size() > 0) {
    LOG(WARNING) << "Kernel extension disabled by file.";
  } else {
    CFURLRef urls[1];
    CFArrayRef directoryArray;

    urls[0] = CFURLCreateWithString(NULL, kKernelExtensionDirectory, NULL);

    directoryArray =
        CFArrayCreate(NULL, (const void **)urls, 1, &kCFTypeArrayCallBacks);
    if (KextManagerLoadKextWithIdentifier(kKernelBundleId, directoryArray) !=
        kOSReturnSuccess) {
    }
    CFRelease(directoryArray);
  }
}

} // namespace osquery
