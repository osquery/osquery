/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <CoreServices/CoreServices.h>

#include <boost/filesystem.hpp>
#include <osquery/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/utils/conversions/darwin/cfdata.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/conversions/darwin/cfnumber.h>

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
    for (int i = 0; i < CFArrayGetCount(static_cast<CFArrayRef>(value)); ++i) {
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
    // might be able to just stringFromCFString after #4778
    CFDataRef df =
        CFStringCreateExternalRepresentation(kCFAllocatorDefault,
                                             static_cast<CFStringRef>(value),
                                             kCFStringEncodingASCII,
                                             '?');
    rvalue = stringFromCFData(df);
    CFRelease(df);
  } else {
    rvalue = "null";
  }

  return rvalue;
}
void genResults(const std::string& path, QueryData& results) {
  CFStringRef cs = CFStringCreateWithCString(
      kCFAllocatorDefault, path.c_str(), kCFStringEncodingASCII);
  MDItemRef mdi = MDItemCreate(kCFAllocatorDefault, cs);
  CFTypeRef tr = MDItemCopyAttribute(mdi, CFSTR("kMDItemPath"));
  CFArrayRef al = MDItemCopyAttributeNames(mdi);
  CFDictionaryRef d = MDItemCopyAttributes(mdi, al);
  for (int j = 0; j < CFArrayGetCount(al); ++j) {
    //Do not release key or value, they are released when the dict is released
    CFTypeRef key = CFArrayGetValueAtIndex(al, j);
    CFTypeRef value = CFDictionaryGetValue(d, key);
    std::string rvalue{"null"};

    if (tr == nullptr || key == nullptr || value == nullptr) {
      continue;
    }

    CFStringRef valuetype = CFCopyTypeIDDescription(CFGetTypeID(value));
    rvalue = getStringOfValue(value, 0);

    Row r;
    r["path"] = stringFromCFString(static_cast<CFStringRef>(tr));
    r["key"] = stringFromCFString(static_cast<CFStringRef>(key));
    r["value"] = rvalue;
    r["valuetype"] = stringFromCFString(static_cast<CFStringRef>(valuetype));
    results.push_back(r);
    CFRelease(valuetype);
  }
  CFRelease(tr);
  CFRelease(al);
  CFRelease(d);
  CFRelease(cs);
}

//Some comment
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
