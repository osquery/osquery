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
#include <IOKit/IOKitLib.h>

#include <optional>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/darwin/iokit_helpers.h>
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

struct AcceleratorStats {
  std::optional<double> utilization_pct;
  std::optional<long long> allocated_vram;
  std::optional<long long> in_use_vram;
};

NSString* normalizeSystemProfilerToken(NSString* value) {
  if (value == nil) {
    return nil;
  }

  if ([value isEqualToString:@"spdisplays_builtin"]) {
    return @"Built-In";
  }

  for (NSString* prefix in @[@"sppci_vendor_", @"spdisplays_", @"sppci_"]) {
    if ([value hasPrefix:prefix]) {
      NSString* token = [value substringFromIndex:[prefix length]];
      token = [token stringByReplacingOccurrencesOfString:@"_" withString:@" "];

      if ([token caseInsensitiveCompare:@"builtin"] == NSOrderedSame) {
        return @"Built-In";
      }

      return [token capitalizedString];
    }
  }

  return value;
}

NSString* parseMetalSupportVersion(NSString* value) {
  if (value == nil) {
    return nil;
  }

  NSString* normalized = normalizeSystemProfilerToken(value);
  if (normalized == nil) {
    return nil;
  }

  if ([normalized hasPrefix:@"Metal"] && [normalized length] > 5) {
    NSString* suffix = [normalized substringFromIndex:5];
    if ([suffix length] > 0) {
      unichar first_char = [suffix characterAtIndex:0];
      if ([[NSCharacterSet decimalDigitCharacterSet] characterIsMember:first_char]) {
        return [@"Metal " stringByAppendingString:suffix];
      }
    }
  }

  return normalized;
}

// Query IOAccelerator services and return their PerformanceStatistics indexed
// in enumeration order. The order generally matches the GPU order returned by
// system_profiler SPDisplaysDataType.
std::vector<AcceleratorStats> collectAcceleratorStats() {
  std::vector<AcceleratorStats> result;

  auto matching = IOServiceMatching("IOAccelerator");
  if (matching == nullptr) {
    return result;
  }

  io_iterator_t raw_it = 0;
  if (IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &raw_it) !=
      KERN_SUCCESS) {
    return result;
  }
  UniqueIoIterator it(raw_it);

  io_service_t raw_service = 0;
  while ((raw_service = IOIteratorNext(it.get())) != 0) {
    UniqueIoService service(raw_service);
    AcceleratorStats stats;

    CFMutableDictionaryRef raw_props = nullptr;
    if (IORegistryEntryCreateCFProperties(
            service.get(), &raw_props, kCFAllocatorDefault, kNilOptions) ==
        KERN_SUCCESS) {
      UniqueCFMutableDictionaryRef props(raw_props);

      // PerformanceStatistics is a dictionary with runtime GPU counters.
      CFTypeRef perf_ref =
          CFDictionaryGetValue(props.get(), CFSTR("PerformanceStatistics"));
      if (perf_ref != nullptr &&
          CFGetTypeID(perf_ref) == CFDictionaryGetTypeID()) {
        CFDictionaryRef perf = static_cast<CFDictionaryRef>(perf_ref);

        // Try known utilization keys in preference order.
        // "Device Utilization %" is used by NVIDIA and AMD on macOS.
        // "GPU Activity(%)" appears on some Intel/integrated GPUs.
        for (CFStringRef key :
             {CFSTR("Device Utilization %"), CFSTR("GPU Activity(%)")}) {
          CFTypeRef val = CFDictionaryGetValue(perf, key);
          if (val != nullptr && CFGetTypeID(val) == CFNumberGetTypeID()) {
            long long pct = 0;
            if (CFNumberGetValue(
                    static_cast<CFNumberRef>(val), kCFNumberSInt64Type, &pct)) {
              stats.utilization_pct = static_cast<double>(pct);
            }
            break;
          }
        }

        // On Apple Silicon, these counters represent GPU memory usage.
        // We use them to estimate memory utilization percentage.
        auto readInt64FromPerf = [&](CFStringRef key,
                                     std::optional<long long>& out_value) {
          CFTypeRef val = CFDictionaryGetValue(perf, key);
          if (val != nullptr && CFGetTypeID(val) == CFNumberGetTypeID()) {
            long long parsed_value = 0;
            if (CFNumberGetValue(static_cast<CFNumberRef>(val),
                                 kCFNumberSInt64Type,
                                 &parsed_value) &&
                parsed_value >= 0) {
              out_value = parsed_value;
            }
          }
        };

        std::optional<long long> used_memory_bytes;
        std::optional<long long> alloc_memory_bytes;
        readInt64FromPerf(CFSTR("In use system memory"), used_memory_bytes);
        readInt64FromPerf(CFSTR("Alloc system memory"), alloc_memory_bytes);

        if (used_memory_bytes.has_value()) {
          stats.in_use_vram = *used_memory_bytes;
        }

        if (alloc_memory_bytes.has_value()) {
          stats.allocated_vram = *alloc_memory_bytes;
        }

      }
    }

    result.push_back(std::move(stats));
  }

  return result;
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

    // Collect IOAccelerator stats once; correlate by index.
    const std::vector<AcceleratorStats> accel_stats = collectAcceleratorStats();

    int gpu_index = 0;
    for (NSDictionary* item in items) {
      Row r;
      r["gpu_index"] = INTEGER(gpu_index);

      // Bus type (e.g., "PCIe", "Built-In") — not a slot address on macOS.
      NSString* bus = [item objectForKey:@"spdisplays_bus"];
      if (bus == nil) {
        bus = [item objectForKey:@"sppci_bus"];
      }
      if (bus != nil) {
        bus = normalizeSystemProfilerToken(bus);
        r["pci_bus"] = SQL_TEXT([bus UTF8String]);
      }

      if (NSString* vendor = [item objectForKey:@"spdisplays_vendor"]) {
        vendor = normalizeSystemProfilerToken(vendor);
        r["vendor_name"] = SQL_TEXT([vendor UTF8String]);
      }

      if (NSString* name = [item objectForKey:@"_name"]) {
        r["device_name"] = SQL_TEXT([name UTF8String]);
      }

      NSString* total_cores = [item objectForKey:@"sppci_cores"];
      if (total_cores == nil) {
        total_cores = [item objectForKey:@"spdisplays_cores"];
      }
      if (total_cores != nil) {
        long long total_cores_value = [total_cores longLongValue];
        if (total_cores_value > 0) {
          r["total_cores"] = INTEGER(total_cores_value);
        }
      }

      // Driver version is not exposed via SPDisplaysDataType. Use Metal
      // support version as a fallback capability marker (for example, Metal 4).
      if (NSString* metal_support =
              [item objectForKey:@"spdisplays_mtlgpufamilysupport"]) {
        NSString* parsed_metal_support =
            parseMetalSupportVersion(metal_support);
        if (parsed_metal_support != nil) {
          r["driver_version"] = SQL_TEXT([parsed_metal_support UTF8String]);
        }
      }

      if (NSString* vram = [item objectForKey:@"spdisplays_vram"]) {
        long long bytes = parseVramToBytes(vram);
        if (bytes > 0) {
          r["vram_total_bytes"] = BIGINT(bytes);
        }
      }

      // GPU utilization from IOAccelerator PerformanceStatistics.
      // Correlation is by index; order generally matches system_profiler.
      if (gpu_index < static_cast<int>(accel_stats.size())) {
        const AcceleratorStats& stats = accel_stats[gpu_index];
        if (stats.allocated_vram.has_value()) {
          r["allocated_vram"] = BIGINT(*stats.allocated_vram);
        }
        if (stats.in_use_vram.has_value()) {
          r["in_use_vram"] = BIGINT(*stats.in_use_vram);
        }
        if (stats.utilization_pct.has_value()) {
          r["gpu_utilization_pct"] = DOUBLE(*stats.utilization_pct);
        }
      }

      // temperature_gpu_celsius, power_draw_watts, power_limit_watts,
      // fan_speed_pct: not available via SPDisplaysDataType or IOAccelerator
      // without vendor-specific IOKit extensions. Left NULL.

      results.push_back(r);
      ++gpu_index;
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery

