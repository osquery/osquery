// Copyright 2004-present Facebook. All Rights Reserved.

#include <CoreFoundation/CoreFoundation.h>

#include <boost/algorithm/string/trim.hpp>

#include "osquery/core.h"
#include "osquery/logger.h"
#include "osquery/tables.h"

extern "C" {
extern CFDictionaryRef OSKextCopyLoadedKextInfo(CFArrayRef, CFArrayRef);
}

namespace osquery {
namespace tables {

QueryData genKextstat(QueryContext &context) {
  QueryData results;
  CFDictionaryRef dict = OSKextCopyLoadedKextInfo(NULL, NULL);

  CFIndex count = CFDictionaryGetCount(dict);
  CFIndex i, j;

  void **keys;
  void **values;

  keys = (void **)malloc(sizeof(void *) * count);
  values = (void **)malloc(sizeof(void *) * count);

  CFDictionaryGetKeysAndValues(
      dict, (const void **)keys, (const void **)values);

  for (i = 0; i < count; i++) {
    for (j = 0; j < count; j++) {
      int kextTag;
      int references;
      unsigned long long load_size;
      unsigned long long wired_size;

      // name
      std::string name;
      CFStringRef nameRef = (CFStringRef)CFDictionaryGetValue(
          (CFDictionaryRef)(values)[j], CFSTR("CFBundleIdentifier"));
      CFIndex nameLen = CFStringGetLength(nameRef) + 1;
      char *nameBuffer = (char *)malloc(nameLen);
      if (nameBuffer &&
          CFStringGetCString(
              nameRef, nameBuffer, nameLen, kCFStringEncodingUTF8)) {
        name = std::string(nameBuffer);
        boost::algorithm::trim(name);
      }
      if (nameBuffer != 0) {
        free(nameBuffer);
      }

      // index
      CFNumberGetValue(
          (CFNumberRef)CFDictionaryGetValue((CFDictionaryRef)values[j],
                                            CFSTR("OSBundleLoadTag")),
          kCFNumberSInt32Type,
          &kextTag);
      if (kextTag != i) {
        continue;
      }

      // refs
      CFNumberGetValue(
          (CFNumberRef)CFDictionaryGetValue((CFDictionaryRef)values[j],
                                            CFSTR("OSBundleRetainCount")),
          kCFNumberSInt32Type,
          &references);

      // size
      CFNumberGetValue(
          (CFNumberRef)CFDictionaryGetValue((CFDictionaryRef)values[j],
                                            CFSTR("OSBundleLoadSize")),
          kCFNumberSInt64Type,
          &load_size);
      char size_c[256] = "";
      snprintf(size_c, sizeof(size_c), "0x%-10llx", load_size);
      std::string size = size_c;
      boost::algorithm::trim(size);

      // wired
      CFNumberGetValue(
          (CFNumberRef)CFDictionaryGetValue((CFDictionaryRef)values[j],
                                            CFSTR("OSBundleWiredSize")),
          kCFNumberSInt64Type,
          &wired_size);
      char wired_c[256] = "";
      snprintf(wired_c, sizeof(wired_c), "0x%-10llx", wired_size);
      std::string wired = wired_c;
      boost::algorithm::trim(wired);

      // version
      std::string version;
      CFStringRef versionRef = (CFStringRef)CFDictionaryGetValue(
          (CFDictionaryRef)values[j], CFSTR("CFBundleVersion"));
      CFIndex versionLen = CFStringGetLength(versionRef) + 1;
      char *versionBuffer = (char *)malloc(versionLen);
      if (versionBuffer &&
          CFStringGetCString(
              versionRef, versionBuffer, versionLen, kCFStringEncodingUTF8)) {
        version = std::string(versionBuffer);
        boost::algorithm::trim(version);
      }
      if (versionBuffer != 0) {
        free(versionBuffer);
      }

      // linked_against
      CFArrayRef dependencies = (CFArrayRef)CFDictionaryGetValue(
          (CFDictionaryRef)values[j], CFSTR("OSBundleDependencies"));
      char linked_against[512] = "";

      if (dependencies != NULL) {
        CFIndex linked_count = CFArrayGetCount(dependencies);
        int linked = 0;

        CFMutableArrayRef marray =
            CFArrayCreateMutableCopy(NULL, linked_count, dependencies);

        CFArraySortValues(marray,
                          CFRangeMake(0, linked_count),
                          (CFComparatorFunction)CFNumberCompare,
                          NULL);

        if (linked_count > 0) {
          snprintf(linked_against, sizeof(linked_against), "<");
        }
        for (int l = 0; l < linked_count; l++) {
          CFNumberGetValue((CFNumberRef)CFArrayGetValueAtIndex(marray, l),
                           kCFNumberSInt32Type,
                           &linked);

          if (l) {
            snprintf(
                linked_against, sizeof(linked_against), "%s ", linked_against);
          }
          snprintf(linked_against,
                   sizeof(linked_against),
                   "%s%d",
                   linked_against,
                   linked);
        }

        CFRelease(marray);

        if (linked_count > 0) {
          snprintf(
              linked_against, sizeof(linked_against), "%s>", linked_against);
        }
      }
      std::string linked_against_string = linked_against;
      boost::algorithm::trim(linked_against_string);

      Row r;
      r["idx"] = INTEGER(kextTag);
      r["refs"] = INTEGER(references);
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
