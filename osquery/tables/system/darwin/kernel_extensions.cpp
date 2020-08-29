/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <IOKit/kext/KextManager.h>
#include <CoreFoundation/CoreFoundation.h>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/darwin/cfnumber.h>
#include <osquery/utils/conversions/darwin/cfstring.h>

namespace osquery {
namespace tables {

inline std::string getKextInt(const CFDictionaryRef &value,
                              const CFStringRef key) {
  auto num = (CFDataRef)CFDictionaryGetValue(value, key);
  return stringFromCFNumber(num, kCFNumberSInt32Type);
}

inline std::string getKextBigInt(const CFDictionaryRef &value,
                                 const CFStringRef key) {
  auto num = (CFDataRef)CFDictionaryGetValue(value, key);
  return stringFromCFNumber(num, kCFNumberSInt64Type);
}

inline std::string getKextString(const CFDictionaryRef &value,
                                 const CFStringRef key) {
  // Some values are optional, meaning the key is empty or does not exist.
  if (!CFDictionaryContainsKey(value, key)) {
    return "";
  }
  auto string = (CFStringRef)CFDictionaryGetValue(value, key);
  if (string == nullptr) {
    return "";
  }

  return stringFromCFString(string);
}

inline std::string getKextLinked(const CFDictionaryRef &value,
                                 const CFStringRef key) {
  std::string result;
  auto links = (CFArrayRef)CFDictionaryGetValue(value, key);
  if (links == nullptr) {
    // Very core.
    return result;
  }

  CFIndex count = CFArrayGetCount(links);
  if (count == 0) {
    // Odd error case, there was a linked value, but an empty list.
    return result;
  }

  auto link_indexes = CFArrayCreateMutableCopy(nullptr, count, links);
  CFArraySortValues(link_indexes,
                    CFRangeMake(0, count),
                    (CFComparatorFunction)CFNumberCompare,
                    nullptr);

  for (int i = 0; i < count; i++) {
    int link;
    CFNumberGetValue((CFNumberRef)CFArrayGetValueAtIndex(link_indexes, i),
                     kCFNumberSInt32Type,
                     (void *)&link);
    if (i > 0) {
      result += " ";
    }
    result += TEXT(link);
  }

  CFRelease(link_indexes);
  // Return in kextstat format for linked extensions.
  return "<" + result + ">";
}

void genExtension(const void *key, const void *value, void *results) {
  if (key == nullptr || value == nullptr || results == nullptr) {
    return;
  }

  // Make sure the extension value is a dictionary
  if (CFGetTypeID((CFTypeRef)value) != CFDictionaryGetTypeID()) {
    return;
  }

  // name
  CFDictionaryRef extension = (CFDictionaryRef)value;
  auto name = getKextString(extension, CFSTR("CFBundleIdentifier"));
  auto idx = getKextInt(extension, CFSTR("OSBundleLoadTag"));

  Row r;
  r["name"] = name;
  r["idx"] = INTEGER(idx);
  r["refs"] = getKextInt(extension, CFSTR("OSBundleRetainCount"));
  r["size"] = getKextBigInt(extension, CFSTR("OSBundleLoadSize"));
  r["version"] = getKextString(extension, CFSTR("CFBundleVersion"));
  r["linked_against"] = getKextLinked(extension, CFSTR("OSBundleDependencies"));
  r["path"] = getKextString(extension, CFSTR("OSBundlePath"));
  ((QueryData *)results)->push_back(r);
}

QueryData genKernelExtensions(QueryContext &context) {
  QueryData results;

  // Populate dict of kernel extensions.
  CFDictionaryRef dict = KextManagerCopyLoadedKextInfo(nullptr, nullptr);
  if (dict == nullptr) {
    return {};
  }

  CFDictionaryApplyFunction(dict, &genExtension, &results);
  CFRelease(dict);
  return results;
}
}
}
