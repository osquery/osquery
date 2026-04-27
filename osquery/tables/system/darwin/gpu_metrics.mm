/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#import <AppKit/NSDocument.h>
#import <Foundation/Foundation.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/darwin/system_profiler.h>

namespace osquery {
namespace tables {

namespace {

// Parse VRAM strings like "8192 MB", "16 GB", "Shared" into bytes.
// Returns -1 when the value is unavailable or shared (unified) memory.
long long parseVramToBytes(NSString* vramStr) {
  if (vramStr == nil) {
    return -1;
  }
  NSString* trimmed = [vramStr
      stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
  if ([trimmed rangeOfString:@"Shared" options:NSCaseInsensitiveSearch]
          .location != NSNotFound) {
    return -1;
  }
  NSArray<NSString*>* parts = [trimmed componentsSeparatedByString:@" "];
  if (parts.count < 2) {
    return -1;
  }
  long long value = [[parts objectAtIndex:0] longLongValue];
  if (value <= 0) {
    return -1;
  }
  NSString* unit = [[parts objectAtIndex:1] uppercaseString];
  if ([unit isEqualToString:@"MB"]) {
    return value * 1024LL * 1024LL;
  } else if ([unit isEqualToString:@"GB"]) {
    return value * 1024LL * 1024LL * 1024LL;
  } else if ([unit isEqualToString:@"TB"]) {
    return value * 1024LL * 1024LL * 1024LL * 1024LL;
  }
  return -1;
}

} // namespace

QueryData genGpuMetrics(QueryContext& context) {
  QueryData results;
  @autoreleasepool {
    NSDictionary* __autoreleasing report = nullptr;
    Status status = getSystemProfilerReport("SPDisplaysDataType", report);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to get GPU metrics: " << status.getMessage();
      return results;
    }

    NSArray* items = [report objectForKey:@"_items"];
    if (items == nil) {
      return results;
    }

    int gpu_index = 0;
    for (NSDictionary* item in items) {
      Row r;
      r["gpu_index"] = INTEGER(gpu_index++);

      // Bus type (e.g., "PCIe", "Built-In") — not a slot address on macOS.
      if (NSString* bus = [item objectForKey:@"spdisplays_bus"]) {
        r["pci_bus"] = SQL_TEXT([bus UTF8String]);
      }

      if (NSString* vendor = [item objectForKey:@"spdisplays_vendor"]) {
        r["vendor_name"] = SQL_TEXT([vendor UTF8String]);
      }

      if (NSString* name = [item objectForKey:@"_name"]) {
        r["device_name"] = SQL_TEXT([name UTF8String]);
      }

      // Driver version is not exposed via SPDisplaysDataType.

      if (NSString* vram = [item objectForKey:@"spdisplays_vram"]) {
        long long bytes = parseVramToBytes(vram);
        if (bytes > 0) {
          r["vram_total_bytes"] = BIGINT(bytes);
        }
      }

      results.push_back(r);
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery
