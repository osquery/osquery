// Copyright 2004-present Facebook. All Rights Reserved.

#include <CoreFoundation/CoreFoundation.h>
#include <iostream>

#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"

using namespace osquery::db;

extern "C" {
extern CFDictionaryRef OSKextCopyLoadedKextInfo(CFArrayRef, CFArrayRef);
}

namespace osquery {
namespace tables {

// Convert a CFString to a standard C string
inline char *cfstring_to_cstring(CFStringRef s) {
  return ((char *)CFStringGetCStringPtr(s, kCFStringEncodingMacRoman));
}

QueryData genKextstat() {
  QueryData results;
  CFDictionaryRef dict = OSKextCopyLoadedKextInfo(NULL, NULL);

  CFIndex count = CFDictionaryGetCount(dict);
  CFIndex i, j;

  void **keys;
  void **values;

  keys = (void **)malloc(sizeof(void *) * count);
  values = (void **)malloc(sizeof(void *) * count);

  CFDictionaryGetKeysAndValues(dict, (const void **)keys,
                               (const void **)values);

  for (i = 0; i < count; i++) {
    for (j = 0; j < count; j++) {
      int kextTag;
      int references;
      unsigned long long load_size;
      unsigned long long wired_size;

      // name
      std::string name =
          std::string(cfstring_to_cstring((CFStringRef)CFDictionaryGetValue(
              (CFDictionaryRef)(values)[j], CFSTR("CFBundleIdentifier"))));

      // index
      CFNumberGetValue(
          (CFNumberRef)CFDictionaryGetValue((CFDictionaryRef)values[j],
                                            CFSTR("OSBundleLoadTag")),
          kCFNumberSInt32Type, &kextTag);
      if (kextTag != i) {
        continue;
      }

      // refs
      CFNumberGetValue(
          (CFNumberRef)CFDictionaryGetValue((CFDictionaryRef)values[j],
                                            CFSTR("OSBundleRetainCount")),
          kCFNumberSInt32Type, &references);

      // size
      CFNumberGetValue(
          (CFNumberRef)CFDictionaryGetValue((CFDictionaryRef)values[j],
                                            CFSTR("OSBundleLoadSize")),
          kCFNumberSInt64Type, &load_size);
      char size_c[256] = "";
      snprintf(size_c, sizeof(size_c), "0x%-10llx", load_size);
      std::string size = size_c;
      boost::algorithm::trim(size);

      // wired
      CFNumberGetValue(
          (CFNumberRef)CFDictionaryGetValue((CFDictionaryRef)values[j],
                                            CFSTR("OSBundleWiredSize")),
          kCFNumberSInt64Type, &wired_size);
      char wired_c[256] = "";
      snprintf(wired_c, sizeof(wired_c), "0x%-10llx", wired_size);
      std::string wired = wired_c;
      boost::algorithm::trim(wired);

      // version
      std::string version =
          std::string(cfstring_to_cstring((CFStringRef)CFDictionaryGetValue(
              (CFDictionaryRef)values[j], CFSTR("CFBundleVersion"))));

      // linked_against
      CFArrayRef dependencies = (CFArrayRef)CFDictionaryGetValue(
          (CFDictionaryRef)values[j], CFSTR("OSBundleDependencies"));
      char linked_against[512] = "";

      if (dependencies != NULL) {
        CFIndex linked_count = CFArrayGetCount(dependencies);
        int linked = 0;

        CFMutableArrayRef marray =
            CFArrayCreateMutableCopy(NULL, linked_count, dependencies);

        CFArraySortValues(marray, CFRangeMake(0, linked_count),
                          (CFComparatorFunction)CFNumberCompare, NULL);

        if (linked_count > 0) {
          snprintf(linked_against, sizeof(linked_against), "<");
        }
        for (int l = 0; l < linked_count; l++) {
          CFNumberGetValue((CFNumberRef)CFArrayGetValueAtIndex(marray, l),
                           kCFNumberSInt32Type, &linked);

          if (l) {
            snprintf(linked_against, sizeof(linked_against), "%s ",
                     linked_against);
          }
          snprintf(linked_against, sizeof(linked_against), "%s%d",
                   linked_against, linked);
        }

        CFRelease(marray);

        if (linked_count > 0) {
          snprintf(linked_against, sizeof(linked_against), "%s>",
                   linked_against);
        }
      }
      std::string linked_against_string = linked_against;
      boost::algorithm::trim(linked_against_string);

      Row r;
      r["idx"] = boost::lexical_cast<std::string>(kextTag);
      r["refs"] = boost::lexical_cast<std::string>(references);
      r["size"] = size;
      r["wired"] = wired;
      r["name"] = name;
      r["version"] = version;
      r["linked_against"] = linked_against_string;
      results.push_back(r);
    }
  }

  CFRelease(dict);
  free(keys);
  free(values);
  return results;
}
}
}
