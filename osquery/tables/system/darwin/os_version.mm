/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cerrno>
#include <sys/utsname.h>

#include <string>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/conversions/split.h>

#import <CoreFoundation/CoreFoundation.h>

namespace osquery {
namespace tables {

// Type used for function pointers to:
// * _CFCopySupplementalVersionDictionary
// * _CFCopySystemVersionDictionary
typedef CFDictionaryRef (*copy_version_t)();

CFDictionaryRef fetchSupplementalVersionDict() {
  // Create a URL ref for the private framework we need
  CFURLRef bundle_url = CFURLCreateWithFileSystemPath(
      kCFAllocatorDefault,
      CFSTR("/System/Library/Frameworks/CoreFoundation.framework"),
      kCFURLPOSIXPathStyle,
      true);

  CFBundleRef bootstrapBundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);

  if (bootstrapBundle == nullptr) {
    CFRelease(bundle_url);
    VLOG(1) << "Failed to load CoreFoundation framework";
    return nullptr;
  }

  copy_version_t copy_version =
      (copy_version_t)CFBundleGetFunctionPointerForName(
          bootstrapBundle, CFSTR("_CFCopySupplementalVersionDictionary"));

  if (copy_version == nullptr) {
    CFRelease(bootstrapBundle);
    CFRelease(bundle_url);
    VLOG(1) << "Failed to load _CFCopySupplementalVersionDictionary function "
               "pointer";
    return nullptr;
  }

  CFDictionaryRef versionDict = copy_version();

  CFRelease(bootstrapBundle);
  CFRelease(bundle_url);

  return versionDict;
}

CFDictionaryRef fetchVersionDict() {
  // Create a URL ref for the private framework we need
  CFURLRef bundle_url = CFURLCreateWithFileSystemPath(
      kCFAllocatorDefault,
      CFSTR("/System/Library/Frameworks/CoreFoundation.framework"),
      kCFURLPOSIXPathStyle,
      true);

  CFBundleRef bootstrapBundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);

  if (bootstrapBundle == nullptr) {
    CFRelease(bundle_url);
    VLOG(1) << "Failed to load CoreFoundation framework";
    return nullptr;
  }

  copy_version_t copy_version =
      (copy_version_t)CFBundleGetFunctionPointerForName(
          bootstrapBundle, CFSTR("_CFCopySystemVersionDictionary"));

  if (copy_version == nullptr) {
    CFRelease(bootstrapBundle);
    CFRelease(bundle_url);
    VLOG(1) << "Failed to load _CFCopySystemVersionDictionary function pointer";
    return nullptr;
  }

  CFDictionaryRef versionDict = copy_version();

  CFRelease(bootstrapBundle);
  CFRelease(bundle_url);

  return versionDict;
}

QueryData genOSVersion(QueryContext& context) {
  QueryData results;
  Row r;

  // Standard values
  r["platform"] = "darwin";
  r["platform_like"] = "darwin";

  // Determine architecture
  struct utsname uname_buf {};

  if (uname(&uname_buf) == 0) {
    r["arch"] = SQL_TEXT(uname_buf.machine);
  } else {
    LOG(INFO) << "Failed to determine the OS architecture, error " << errno;
  }

  // Fetch base version data available on all systems
  CFDictionaryRef smallVersionDict = fetchVersionDict();

  if (smallVersionDict) {
    auto count = CFDictionaryGetCount(smallVersionDict);
    std::vector<const void*> keys(count);
    std::vector<const void*> values(count);
    CFDictionaryGetKeysAndValues(smallVersionDict, keys.data(), values.data());

    for (CFIndex i = 0; i < count; i++) {
      auto key = stringFromCFString((CFStringRef)keys[i]);
      auto value = stringFromCFString((CFStringRef)values[i]);

      // switch on key name to each value
      if (key == "ProductBuildVersion") {
        r["build"] = value;
      } else if (key == "ProductName") {
        r["name"] = value;
      } else if (key == "ProductVersion") {
        r["version"] = value;

        // Break out version parts
        auto version = osquery::split(value, ".");
        switch (version.size()) {
        case 3:
          r["patch"] = INTEGER(version[2]);
        case 2:
          r["minor"] = INTEGER(version[1]);
        case 1:
          r["major"] = INTEGER(version[0]);
          break;
        }
      }
    }

    CFRelease(smallVersionDict);
  }

  // Fetch supplemental version data available in modern versions
  CFDictionaryRef fullVersionDict = fetchSupplementalVersionDict();

  if (fullVersionDict) {
    auto count = CFDictionaryGetCount(fullVersionDict);
    std::vector<const void*> keys(count);
    std::vector<const void*> values(count);
    CFDictionaryGetKeysAndValues(fullVersionDict, keys.data(), values.data());

    for (CFIndex i = 0; i < count; i++) {
      auto key = stringFromCFString((CFStringRef)keys[i]);
      auto value = stringFromCFString((CFStringRef)values[i]);

      // switch on key name to each value
      if (key == "ShortVersionString") {
        r["version"] = value; // If we get a more detailed version in
                              // supplemental call, use it
      } else if (key == "ProductVersionExtra") {
        r["extra"] = value;
      } else if (key == "ProductBuildVersion") {
        r["build"] = value;
      }
    }

    CFRelease(fullVersionDict);
  } else {
    VLOG(1) << "Failed to query supplemental version information";
  }

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
