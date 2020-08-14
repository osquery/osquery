/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreServices/CoreServices.h>

#include <boost/filesystem.hpp>
#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/darwin/cfdata.h>
#include <osquery/utils/conversions/darwin/cfnumber.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/scope_guard.h>

namespace osquery {
namespace tables {

const int MAX_RECURSION_DEPTH = 2;

std::string getStringOfValue(CFTypeRef value, int depth) {
  if (depth >= MAX_RECURSION_DEPTH) {
    return "";
  }
  std::string rvalue;

  if (CFGetTypeID(value) == CFNumberGetTypeID()) {
    rvalue = stringFromCFNumber(static_cast<CFDataRef>(value));
  } else if (CFGetTypeID(value) == CFDateGetTypeID()) {
    auto unix_time = CFDateGetAbsoluteTime(static_cast<CFDateRef>(value)) +
                     kCFAbsoluteTimeIntervalSince1970;
    rvalue = INTEGER(std::llround(unix_time));
  } else if (CFGetTypeID(value) == CFArrayGetTypeID()) {
    for (auto i = 0; i < CFArrayGetCount(static_cast<CFArrayRef>(value)); ++i) {
      CFTypeRef b = CFArrayGetValueAtIndex(static_cast<CFArrayRef>(value), i);
      if (i == 0) {
        rvalue = getStringOfValue(b, depth + 1);
      } else {
        // beware of recursion....
        rvalue = rvalue + "," + getStringOfValue(b, depth + 1);
      }
    }
  } else if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
    if (CFBooleanGetValue(static_cast<CFBooleanRef>(value))) {
      rvalue = "true";
    } else {
      rvalue = "false";
    }
  } else if (CFGetTypeID(value) == CFStringGetTypeID()) {
    rvalue = stringFromCFString(static_cast<CFStringRef>(value));
  } else {
    rvalue = "null";
  }

  return rvalue;
}

void genResults(const std::string& path, QueryData& results) {
  CFStringRef cs = CFStringCreateWithCString(
      kCFAllocatorDefault, path.c_str(), kCFStringEncodingASCII);
  if (cs == nullptr) {
    return;
  }
  auto const cs_guard = scope_guard::create([&cs]() { CFRelease(cs); });

  MDItemRef mdi = MDItemCreate(kCFAllocatorDefault, cs);
  if (mdi == nullptr) {
    return;
  }
  auto const mdi_guard = scope_guard::create([&mdi]() { CFRelease(mdi); });

  CFTypeRef tr = MDItemCopyAttribute(mdi, CFSTR("kMDItemPath"));
  if (tr == nullptr) {
    return;
  }
  auto const tr_guard = scope_guard::create([&tr]() { CFRelease(tr); });

  CFArrayRef al = MDItemCopyAttributeNames(mdi);
  if (al == nullptr) {
    return;
  }
  auto const al_guard = scope_guard::create([&al]() { CFRelease(al); });

  CFDictionaryRef d = MDItemCopyAttributes(mdi, al);
  if (d == nullptr) {
    return;
  }
  auto const d_guard = scope_guard::create([&d]() { CFRelease(d); });

  for (int j = 0; j < CFArrayGetCount(al); ++j) {
    // Do not release key or value, they are released when the dict is released
    CFTypeRef key = CFArrayGetValueAtIndex(al, j);
    CFTypeRef value = CFDictionaryGetValue(d, key);
    std::string rvalue{"null"};

    if (key == nullptr || value == nullptr) {
      continue;
    }

    CFStringRef valuetype = CFCopyTypeIDDescription(CFGetTypeID(value));
    if (valuetype == nullptr) {
      return;
    }
    auto const guard =
        scope_guard::create([&valuetype]() { CFRelease(valuetype); });

    rvalue = getStringOfValue(value, 0);

    Row r;
    r["path"] = stringFromCFString(static_cast<CFStringRef>(tr));
    r["key"] = stringFromCFString(static_cast<CFStringRef>(key));
    r["value"] = rvalue;
    r["valuetype"] = stringFromCFString(static_cast<CFStringRef>(valuetype));
    results.push_back(r);
  }
}

QueryData genMdlsResults(QueryContext& context) {
  QueryData results;
  // Resolve file paths for EQUALS and LIKE operations.
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    boost::system::error_code ec;
    if (!(boost::filesystem::is_regular_file(path, ec) ||
          boost::filesystem::is_directory(path, ec))) {
      continue;
    }
    genResults(path.string(), results);
  }
  return results;
}
}
}
