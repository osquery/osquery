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

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <unistd.h>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/darwin/iokit_helpers.h>
#include <osquery/utils/darwin/system_profiler.h>
#include <osquery/utils/scope_guard.h>

// IOReport public API declarations (from libIOReport.dylib - same ABI used by
// powermetrics). These symbols are exported in the SDK's libIOReport.tbd.
extern "C" {
typedef struct _IOReportSubscriptionRef* IOReportSubscriptionRef;

// Returns all available channels.
CFMutableDictionaryRef IOReportCopyAllChannels(uint64_t a, uint64_t b);

// Creates a subscription for the desired channels. subbedChannels is output.
IOReportSubscriptionRef IOReportCreateSubscription(
    void* self,
    CFMutableDictionaryRef desired_channels,
    CFMutableDictionaryRef* subbed_channels,
    uint64_t channel_id,
    CFTypeRef options);

// Takes a sample snapshot from a subscription. Returns a CFDictionaryRef.
CFDictionaryRef IOReportCreateSamples(IOReportSubscriptionRef sub,
                                      CFMutableDictionaryRef subbed_channels,
                                      CFTypeRef options);

// Computes the delta between two samples.
CFDictionaryRef IOReportCreateSamplesDelta(CFDictionaryRef prev,
                                           CFDictionaryRef next,
                                           CFTypeRef options);

// Iterates over each channel entry in a sample set via a callback block.
int IOReportIterate(CFDictionaryRef samples,
                    int (^block)(CFDictionaryRef channel_item));

// Returns the channel name string for a channel item.
CFStringRef IOReportChannelGetChannelName(CFDictionaryRef channel_item);

// Returns the group name string for a channel item.
CFStringRef IOReportChannelGetGroup(CFDictionaryRef channel_item);

// Returns the unit label string for a channel item (for example: uW, mW).
CFStringRef IOReportChannelGetUnitLabel(CFDictionaryRef channel_item);

// Extracts the integer value from a simple-format channel item.
int64_t IOReportSimpleGetIntegerValue(CFDictionaryRef channel_item,
                                      int32_t* residual);
}

namespace osquery {
namespace tables {

namespace {

// Case-insensitive substring search
bool containsCaseInsensitive(CFStringRef haystack, CFStringRef needle) {
  if (haystack == nullptr || needle == nullptr) {
    return false;
  }

  return CFStringFind(haystack, needle, kCFCompareCaseInsensitive).location !=
         kCFNotFound;
}

bool isInvalidCounterValue(int64_t value) {
  return value == std::numeric_limits<int64_t>::min();
}

std::string safeStringFromCFString(CFTypeRef cf_object) {
  if (cf_object == nullptr || CFGetTypeID(cf_object) != CFStringGetTypeID()) {
    return {};
  }

  return stringFromCFString(static_cast<CFStringRef>(cf_object));
}

enum class PowerUnit {
  EmptyOrMissing,
  NanoWatt,
  MicroWatt,
  MilliWatt,
  Watt,
  MicroJoule,
  MilliJoule,
  Joule,
  Unknown,
};

PowerUnit getPowerUnit(CFStringRef unit_label) {
  if (unit_label == nullptr) {
    return PowerUnit::EmptyOrMissing;
  }

  char unit_buf[32] = {0};
  CFStringGetCString(
      unit_label, unit_buf, sizeof(unit_buf), kCFStringEncodingUTF8);

  if (strcmp(unit_buf, "uW") == 0 || strcmp(unit_buf, "µW") == 0) {
    return PowerUnit::MicroWatt;
  }

  if (strcmp(unit_buf, "mW") == 0) {
    return PowerUnit::MilliWatt;
  }

  if (strcmp(unit_buf, "nW") == 0) {
    return PowerUnit::NanoWatt;
  }

  if (strcmp(unit_buf, "W") == 0) {
    return PowerUnit::Watt;
  }

  if (strcmp(unit_buf, "uJ") == 0 || strcmp(unit_buf, "µJ") == 0) {
    return PowerUnit::MicroJoule;
  }

  if (strcmp(unit_buf, "mJ") == 0) {
    return PowerUnit::MilliJoule;
  }

  if (strcmp(unit_buf, "J") == 0) {
    return PowerUnit::Joule;
  }

  if (unit_buf[0] == '\0') {
    return PowerUnit::EmptyOrMissing;
  }

  return PowerUnit::Unknown;
}

double convertToWatts(int64_t value,
                      PowerUnit unit,
                      double sample_interval_seconds) {
  double channel_power_w = static_cast<double>(value);

  switch (unit) {
  case PowerUnit::NanoWatt:
    channel_power_w /= 1000000000.0;
    break;
  case PowerUnit::MicroWatt:
    channel_power_w /= 1000000.0;
    break;
  case PowerUnit::MilliWatt:
    channel_power_w /= 1000.0;
    break;
  case PowerUnit::Watt:
    break;
  case PowerUnit::MicroJoule:
    channel_power_w = (channel_power_w / 1000000.0) / sample_interval_seconds;
    break;
  case PowerUnit::MilliJoule:
    channel_power_w = (channel_power_w / 1000.0) / sample_interval_seconds;
    break;
  case PowerUnit::Joule:
    channel_power_w /= sample_interval_seconds;
    break;
  case PowerUnit::EmptyOrMissing:
    // For Energy Model rails, empty unit has historically meant microwatts.
    channel_power_w /= 1000000.0;
    break;
  case PowerUnit::Unknown:
    return 0.0;
  }

  return channel_power_w;
}

bool isGpuPowerCandidateChannel(CFStringRef group, CFStringRef name) {
  const bool group_has_gpu = containsCaseInsensitive(group, CFSTR("GPU"));
  const bool name_has_gpu = containsCaseInsensitive(name, CFSTR("GPU"));
  const bool has_power = containsCaseInsensitive(group, CFSTR("Power")) ||
                         containsCaseInsensitive(name, CFSTR("Power"));
  const bool has_energy = containsCaseInsensitive(group, CFSTR("Energy")) ||
                          containsCaseInsensitive(name, CFSTR("Energy"));

  if (!((group_has_gpu || name_has_gpu) && (has_power || has_energy))) {
    return false;
  }

  // Skip cumulative counters whose channel name is itself "...Energy".
  return !containsCaseInsensitive(name, CFSTR("Energy"));
}

// Collect GPU power by scanning all IOReport channels once and extracting
// GPU-related power/energy channels from a sample delta window.
std::vector<std::optional<double>> collectGPUPowerData() {
  std::vector<std::optional<double>> power_data;

  @autoreleasepool {
    constexpr useconds_t kSampleIntervalUs = 500U * 1000U;
    constexpr double kSampleIntervalSeconds = 0.5;

    CFMutableDictionaryRef all_channels = IOReportCopyAllChannels(0, 0);
    if (all_channels == nullptr) {
      LOG(INFO) << "No IOReport channels available";
      return power_data;
    }
    const auto all_channels_guard = scope_guard::CFRelease(all_channels);

    CFMutableDictionaryRef subbed_channels = nullptr;
    IOReportSubscriptionRef sub = IOReportCreateSubscription(
        nullptr, all_channels, &subbed_channels, 0, nullptr);
    const auto subbed_channels_guard = scope_guard::CFRelease(subbed_channels);

    if (sub == nullptr || subbed_channels == nullptr) {
      LOG(WARNING) << "IOReportCreateSubscription returned null";
      return power_data;
    }

    CFDictionaryRef sample_a =
        IOReportCreateSamples(sub, subbed_channels, nullptr);
    const auto sample_a_guard = scope_guard::CFRelease(sample_a);
    if (sample_a == nullptr) {
      LOG(WARNING) << "IOReportCreateSamples (first) returned null";
      return power_data;
    }

    usleep(kSampleIntervalUs);

    CFDictionaryRef sample_b =
        IOReportCreateSamples(sub, subbed_channels, nullptr);
    const auto sample_b_guard = scope_guard::CFRelease(sample_b);
    if (sample_b == nullptr) {
      LOG(WARNING) << "IOReportCreateSamples (second) returned null";
      return power_data;
    }

    CFDictionaryRef delta =
        IOReportCreateSamplesDelta(sample_a, sample_b, nullptr);
    const auto delta_guard = scope_guard::CFRelease(delta);

    if (delta == nullptr) {
      LOG(WARNING) << "IOReportCreateSamplesDelta returned null";
      return power_data;
    }

    __block double total_power_w = 0.0;
    __block int logged = 0;
    __block bool found_gpu_channel = false;

    IOReportIterate(delta, ^int(CFDictionaryRef channel_item) {
      CFStringRef group = IOReportChannelGetGroup(channel_item);
      CFStringRef name = IOReportChannelGetChannelName(channel_item);
      if (group == nullptr || name == nullptr) {
        return 0;
      }

      if (!isGpuPowerCandidateChannel(group, name)) {
        return 0;
      }

      int32_t residual = 0;
      const int64_t value =
          IOReportSimpleGetIntegerValue(channel_item, &residual);
      if (isInvalidCounterValue(value) || value < 0) {
        return 0;
      }

      CFStringRef unit = IOReportChannelGetUnitLabel(channel_item);
      const auto power_unit = getPowerUnit(unit);
      if (power_unit == PowerUnit::Unknown) {
        return 0;
      }

      found_gpu_channel = true;

      const double channel_power_w =
          convertToWatts(value, power_unit, kSampleIntervalSeconds);
      total_power_w += channel_power_w;

      if (logged < 20) {
        const auto group_string = safeStringFromCFString(group);
        const auto name_string = safeStringFromCFString(name);
        const auto unit_string = safeStringFromCFString(unit);

        LOG(INFO) << "IOReport(all) GPU power candidate group='" << group_string
                  << "' name='" << name_string << "' value=" << value
                  << " unit='" << unit_string << "' watts=" << channel_power_w;
        ++logged;
      }

      return 0;
    });

    if (found_gpu_channel) {
      LOG(INFO) << "Total GPU power from all-channel scan: " << total_power_w
                << " W";
      power_data.push_back(total_power_w);
    } else {
      LOG(INFO) << "All-channel GPU power scan found no matching candidates";
    }
  }

  return power_data;
}

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
  std::optional<double> power_draw_watts;
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

  for (NSString* prefix in @[ @"sppci_vendor_", @"spdisplays_", @"sppci_" ]) {
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
      if ([[NSCharacterSet decimalDigitCharacterSet]
              characterIsMember:first_char]) {
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

  // Collect GPU power data via private framework (once for all GPUs)
  const auto gpu_power_data = collectGPUPowerData();

  io_service_t raw_service = 0;
  int gpu_index = 0;
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

    // Correlate power data by GPU index
    if (gpu_index < static_cast<int>(gpu_power_data.size())) {
      stats.power_draw_watts = gpu_power_data[gpu_index];
    }

    result.push_back(std::move(stats));
    ++gpu_index;
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
        if (stats.power_draw_watts.has_value()) {
          r["power_draw_watts"] = DOUBLE(*stats.power_draw_watts);
        }
      }

      // temperature_gpu_celsius, power_limit_watts, fan_speed_pct:
      // not available via public APIs. Left NULL.

      results.push_back(r);
      ++gpu_index;
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery
