/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#import <Foundation/Foundation.h>

#include <IOKit/IOKitKeys.h>
#include <IOKit/IOKitLib.h>

#include <cstdio>
#include <cstring>
#include <iomanip>
#include <optional>
#include <sstream>
#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/darwin/cfdata.h>
#include <osquery/utils/conversions/darwin/cfnumber.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/darwin/iokit_helpers.h>
#include <osquery/utils/darwin/system_profiler.h>

namespace osquery {
namespace tables {

namespace {

const char* kIOAcceleratorClassName = "IOAccelerator";

// An IOKit accelerator node plus the hardware identity of the device it
// drives, used to match accelerators to system_profiler rows.
struct IOKitGpuInfo {
  std::string vendor_id;
  std::string model_id;
  std::string model;
  std::string driver;
  std::uint32_t cores = 0;
  // GPU utilization from PerformanceStatistics, if available.
  std::optional<double> utilization_pct;
  // PCI vendor/device IDs published by the underlying device node (e.g.
  // sgx@4000000 on Apple Silicon, IOPCIDevice for discrete GPUs), if any.
  std::string pci_vendor_id;
  std::string pci_device_id;
  // Bus address of the underlying PCI device (the IOKit pcidebug property,
  // e.g. "0:5:0"), in the same form as the darwin pci_devices table.
  std::string pci_slot;
};

using IOKitGpuInfoList = std::vector<IOKitGpuInfo>;

std::string cfDataToHexString(CFDataRef data) {
  if (data == nullptr) {
    return {};
  }

  auto length = CFDataGetLength(data);
  if (length < 1) {
    return {};
  }

  const UInt8* bytes = CFDataGetBytePtr(data);
  // The value is stored little-endian; reverse for human-readable hex. The
  // high-order bytes are padding (vendor-id/device-id are 16-bit), so start
  // at the last nonzero byte: <6b100000> is "0x106b", not "0x0000106b",
  // matching the IDs system_profiler reports.
  CFIndex start = length - 1;
  while (start > 0 && bytes[start] == 0) {
    --start;
  }
  if (bytes[start] == 0) {
    return {};
  }

  std::stringstream ss;
  ss << "0x" << std::hex << std::setfill('0');
  for (CFIndex i = start; i >= 0; --i) {
    ss << std::setw(2) << static_cast<int>(bytes[i]);
  }
  return ss.str();
}

std::uint64_t cfNumberToUint64(CFTypeRef value) {
  if (value == nullptr || CFGetTypeID(value) != CFNumberGetTypeID()) {
    return 0;
  }
  long long int n = 0;
  CFNumberGetValue(static_cast<CFNumberRef>(value), kCFNumberLongLongType, &n);
  return static_cast<std::uint64_t>(n);
}

// Safely convert an IOKit property that may be either a CFString or a CFData
// holding a (possibly unterminated) C string. IOKit does not guarantee property
// types across vendors; on PCI device nodes, "model" is conventionally CFData.
std::string stringFromIOKitProperty(CFTypeRef value) {
  if (value == nullptr) {
    return {};
  }

  auto type_id = CFGetTypeID(value);
  if (type_id == CFStringGetTypeID()) {
    return stringFromCFString(static_cast<CFStringRef>(value));
  }

  if (type_id == CFDataGetTypeID()) {
    auto data = static_cast<CFDataRef>(value);
    auto length = CFDataGetLength(data);
    if (length < 1) {
      return {};
    }
    // The data bytes may not be null terminated; use strnlen against the
    // CFDataGetLength bound.
    auto bytes = CFDataGetBytePtr(data);
    auto* begin = reinterpret_cast<const char*>(bytes);
    auto str_length = strnlen(begin, static_cast<std::size_t>(length));
    return std::string(begin, str_length);
  }

  return {};
}

// Read the PCI identity of a device node: the vendor-id / device-id
// properties and the pcidebug bus address. On Apple Silicon the device node
// (e.g. sgx@4000000) has none of them, in which case this returns false and
// callers fall back to model-based matching.
bool readPciInfoFromEntry(io_registry_entry_t entry, IOKitGpuInfo& info) {
  info.pci_vendor_id.clear();
  info.pci_device_id.clear();
  info.pci_slot.clear();

  CFMutableDictionaryRef props = nullptr;
  auto kr = IORegistryEntryCreateCFProperties(
      entry, &props, kCFAllocatorDefault, kNilOptions);
  if (kr != KERN_SUCCESS || props == nullptr) {
    return false;
  }
  UniqueCFMutableDictionaryRef props_ptr(props);

  bool found = false;
  auto vid = CFDictionaryGetValue(props, CFSTR("vendor-id"));
  if (vid != nullptr && CFGetTypeID(vid) == CFDataGetTypeID()) {
    info.pci_vendor_id = cfDataToHexString(static_cast<CFDataRef>(vid));
    found = !info.pci_vendor_id.empty();
  }
  auto did = CFDictionaryGetValue(props, CFSTR("device-id"));
  if (did != nullptr && CFGetTypeID(did) == CFDataGetTypeID()) {
    info.pci_device_id = cfDataToHexString(static_cast<CFDataRef>(did));
  }

  // Bus address (e.g. "0:5:0"); the same pcidebug value the darwin
  // pci_devices table reports as pci_slot.
  info.pci_slot =
      stringFromIOKitProperty(CFDictionaryGetValue(props, CFSTR("pcidebug")));

  return found;
}

// Walk from the accelerator to its parent device node and read its PCI
// identity (vendor/device IDs and the bus address), falling back to the
// accelerator's own properties (Apple Silicon accelerators publish
// vendor-id directly).
void acceleratorPciIdentity(io_service_t accelerator, IOKitGpuInfo& info) {
  io_registry_entry_t parent = 0;
  if (IORegistryEntryGetParentEntry(accelerator, "IOService", &parent) ==
          KERN_SUCCESS &&
      parent != 0) {
    UniqueIoService parent_ptr(parent);
    readPciInfoFromEntry(parent, info);
  }

  if (info.pci_vendor_id.empty()) {
    // Fall back to the accelerator's own vendor-id (e.g. Apple Silicon).
    CFMutableDictionaryRef props = nullptr;
    auto kr = IORegistryEntryCreateCFProperties(
        accelerator, &props, kCFAllocatorDefault, kNilOptions);
    if (kr == KERN_SUCCESS && props != nullptr) {
      UniqueCFMutableDictionaryRef props_ptr(props);
      auto vid = CFDictionaryGetValue(props, CFSTR("vendor-id"));
      if (vid != nullptr && CFGetTypeID(vid) == CFDataGetTypeID()) {
        info.pci_vendor_id = cfDataToHexString(static_cast<CFDataRef>(vid));
      }
    }
  }
}

// Collect every IOAccelerator node with its properties, so rows can be
// matched by hardware identity instead of by display name.
IOKitGpuInfoList collectIOKitGpus() {
  IOKitGpuInfoList gpus;

  auto matching = IOServiceMatching(kIOAcceleratorClassName);
  if (matching == nullptr) {
    return gpus;
  }

  // kIOMasterPortDefault is deprecated since macOS 12; kIOMainPortDefault is
  // unavailable before it. The deployment target is 10.15, so select at
  // compile time and fall back to the deprecated constant on older systems.
  mach_port_t main_port;
#ifdef kIOMainPortDefault
  main_port = kIOMainPortDefault;
#else
  main_port = kIOMasterPortDefault;
#endif

  io_iterator_t it = 0;
  auto kr = IOServiceGetMatchingServices(main_port, matching, &it);
  if (kr != KERN_SUCCESS) {
    return gpus;
  }
  UniqueIoIterator it_ptr(it);

  io_service_t service = 0;
  while ((service = IOIteratorNext(it_ptr.get())) != 0) {
    UniqueIoService service_ptr(service);

    CFMutableDictionaryRef props = nullptr;
    kr = IORegistryEntryCreateCFProperties(
        service, &props, kCFAllocatorDefault, kNilOptions);
    if (kr != KERN_SUCCESS || props == nullptr) {
      continue;
    }
    UniqueCFMutableDictionaryRef props_ptr(props);

    IOKitGpuInfo info;

    // model: matched against the row below; may be CFString or CFData.
    auto model_cf = CFDictionaryGetValue(props, CFSTR("model"));
    info.model = stringFromIOKitProperty(model_cf);

    // vendor-id: CFDataRef, 4 bytes, little-endian.
    auto vendor_id_data =
        static_cast<CFDataRef>(CFDictionaryGetValue(props, CFSTR("vendor-id")));
    if (vendor_id_data != nullptr &&
        CFGetTypeID(vendor_id_data) == CFDataGetTypeID()) {
      info.vendor_id = cfDataToHexString(vendor_id_data);
    }

    // driver: IOClass property.
    info.driver =
        stringFromIOKitProperty(CFDictionaryGetValue(props, CFSTR("IOClass")));

    // model_id: IONameMatched (e.g. "gpu,t6000") identifies the SoC GPU
    // variant. On Apple Silicon there is no PCI device-id; this is the closest
    // hardware identifier.
    auto name_matched = CFDictionaryGetValue(props, CFSTR("IONameMatched"));
    info.model_id = stringFromIOKitProperty(name_matched);

    // cores: gpu-core-count (CFNumberRef).
    auto cores_cf = CFDictionaryGetValue(props, CFSTR("gpu-core-count"));
    if (cores_cf != nullptr) {
      info.cores = static_cast<std::uint32_t>(cfNumberToUint64(cores_cf));
    }

    // GPU utilization from PerformanceStatistics.
    // "Device Utilization %" is used by NVIDIA and AMD on macOS.
    // "GPU Activity(%)" appears on some Intel/integrated GPUs.
    CFTypeRef perf_ref =
        CFDictionaryGetValue(props, CFSTR("PerformanceStatistics"));
    if (perf_ref != nullptr &&
        CFGetTypeID(perf_ref) == CFDictionaryGetTypeID()) {
      CFDictionaryRef perf = static_cast<CFDictionaryRef>(perf_ref);
      for (CFStringRef key :
           {CFSTR("Device Utilization %"), CFSTR("GPU Activity(%)")}) {
        CFTypeRef val = CFDictionaryGetValue(perf, key);
        if (val != nullptr && CFGetTypeID(val) == CFNumberGetTypeID()) {
          long long pct = 0;
          if (CFNumberGetValue(
                  static_cast<CFNumberRef>(val), kCFNumberSInt64Type, &pct)) {
            info.utilization_pct = static_cast<double>(pct);
          }
          break;
        }
      }
    }

    // vram: deliberately not populated from PerformanceStatistics. The only
    // candidate there, "Alloc system memory", is the memory *currently*
    // allocated to the GPU and fluctuates with load (verified empirically:
    // 7.26 GB vs 7.33 GB minutes apart on the same machine). Every other
    // platform reports fixed capacity in this column; a dynamic value would
    // surface as a row change on every poll and break diff-based monitoring.
    // Apple Silicon has no dedicated VRAM, so the column stays empty here;
    // system_profiler's spdisplays_vram still fills it for discrete GPUs.

    acceleratorPciIdentity(service, info);

    gpus.push_back(std::move(info));
  }

  return gpus;
}

// Find the best accelerator for a system_profiler row: prefer a hardware
// identity match (PCI vendor/device IDs), then fall back to model name. Each
// accelerator is consumed at most once so two identical cards enrich two
// different rows instead of the same node twice.
IOKitGpuInfoList::iterator matchAccelerator(const std::string& model_name,
                                            const std::string& sp_vendor_id,
                                            const std::string& sp_device_id,
                                            IOKitGpuInfoList& gpus) {
  if (!sp_vendor_id.empty() && !sp_device_id.empty()) {
    for (auto it = gpus.begin(); it != gpus.end(); ++it) {
      if (it->pci_vendor_id == sp_vendor_id &&
          it->pci_device_id == sp_device_id) {
        return it;
      }
    }
  }

  if (model_name.empty()) {
    return gpus.end();
  }

  for (auto it = gpus.begin(); it != gpus.end(); ++it) {
    if (it->model == model_name) {
      return it;
    }
  }

  return gpus.end();
}

std::uint64_t vramBytesFromDict(NSDictionary* item) {
  id vram = [item valueForKey:@"spdisplays_vram"];
  if (vram == nil) {
    return 0;
  }

  if ([vram isKindOfClass:[NSNumber class]]) {
    return [vram unsignedLongLongValue];
  }

  NSString* vram_str = [vram description];
  std::string raw([vram_str UTF8String]);

  double multiplier = 0;
  if (raw.find("GB") != std::string::npos) {
    multiplier = 1024.0 * 1024.0 * 1024.0;
  } else if (raw.find("MB") != std::string::npos) {
    multiplier = 1024.0 * 1024.0;
  } else if (raw.find("KB") != std::string::npos) {
    multiplier = 1024.0;
  }

  if (multiplier == 0) {
    return 0;
  }

  try {
    return static_cast<std::uint64_t>(std::stod(raw) * multiplier);
  } catch (const std::exception&) {
    return 0;
  }
}

std::string stripPrefix(const std::string& str, const std::string& prefix) {
  if (str.find(prefix) == 0) {
    return str.substr(prefix.size());
  }
  return str;
}

} // namespace

QueryData genGpuInfo(QueryContext& context) {
  QueryData results;

  @autoreleasepool {
    NSDictionary* __autoreleasing result;
    Status status = getSystemProfilerReport("SPDisplaysDataType", result);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to get GPU information: " << status.getMessage();
      return results;
    }

    NSArray* items = [result objectForKey:@"_items"];
    if (items == nil) {
      return results;
    }

    std::int32_t device_id = 0;

    // Collect IOKit accelerators once; each row consumes at most one node so
    // identical GPUs are enriched from distinct accelerators.
    IOKitGpuInfoList iokit_gpus = collectIOKitGpus();

    for (NSDictionary* item in items) {
      Row r;

      std::string model_name;

      if (id name = [item valueForKey:@"_name"]) {
        r["name"] = SQL_TEXT([[name description] UTF8String]);
        model_name = r["name"];
      }

      if (id model = [item valueForKey:@"sppci_model"]) {
        if (r["name"].empty()) {
          r["name"] = SQL_TEXT([[model description] UTF8String]);
          model_name = r["name"];
        }
        r["model"] = SQL_TEXT([[model description] UTF8String]);
        if (model_name.empty()) {
          model_name = r["model"];
        }
      }

      if (id vendor = [item valueForKey:@"spdisplays_vendor"]) {
        std::string vendor_str([[vendor description] UTF8String]);
        r["vendor"] = SQL_TEXT(stripPrefix(vendor_str, "sppci_vendor_"));
      }

      if (id driver = [item valueForKey:@"spdisplays_driver"]) {
        r["driver"] = SQL_TEXT([[driver description] UTF8String]);
      }

      auto vram = vramBytesFromDict(item);
      if (vram > 0) {
        r["vram"] = BIGINT(vram);
      }

      r["pci_class_id"] = "0x030000";

      // Hardware identity from system_profiler, used to match the row to its
      // IOKit accelerator and to fill the identity columns: discrete GPUs
      // report hex PCI ids (e.g. "0x1002" / "0x679e"); Apple Silicon does
      // not report them and falls through to the IOKit enrichment below.
      std::string sp_vendor_id;
      std::string sp_device_id;
      if (id sp_vid = [item valueForKey:@"sppci_vendor_id"]) {
        sp_vendor_id = [[sp_vid description] UTF8String];
        r["vendor_id"] = sp_vendor_id;
      }
      if (id sp_did = [item valueForKey:@"sppci_device_id"]) {
        sp_device_id = [[sp_did description] UTF8String];
        r["model_id"] = sp_device_id;
      }

      // Enrich from IOKit AGXAccelerator for Apple Silicon (and discrete GPUs
      // that publish an IOAccelerator personality), matched by hardware
      // identity when available.
      auto accel_it =
          matchAccelerator(model_name, sp_vendor_id, sp_device_id, iokit_gpus);
      if (accel_it != iokit_gpus.end()) {
        const auto& iokit_info = *accel_it;
        if (r["vendor_id"].empty() && !iokit_info.vendor_id.empty()) {
          r["vendor_id"] = iokit_info.vendor_id;
        }
        if (r["model_id"].empty() && !iokit_info.model_id.empty()) {
          r["model_id"] = iokit_info.model_id;
        }
        if (r["driver"].empty() && !iokit_info.driver.empty()) {
          r["driver"] = iokit_info.driver;
        }
        // pci_slot: the IOKit bus address of the underlying PCI device.
        // Apple Silicon GPUs have no PCI node, so the column stays empty
        // there.
        if (!iokit_info.pci_slot.empty()) {
          r["pci_slot"] = iokit_info.pci_slot;
        }
        if (iokit_info.cores > 0) {
          r["cores"] = INTEGER(iokit_info.cores);
        }
        if (iokit_info.utilization_pct.has_value()) {
          r["gpu_utilization_pct"] = DOUBLE(*iokit_info.utilization_pct);
        }
        // Consume this accelerator so no other row matches it.
        iokit_gpus.erase(accel_it);
      }

      // device_id: derived from the slot when present so it is stable across
      // reboots; system_profiler enumeration order is not guaranteed. The
      // counter is only a fallback for rows without one (e.g. Apple Silicon
      // integrated GPUs).
      if (r["pci_slot"].empty()) {
        r["device_id"] = "GPU" + std::to_string(device_id++);
      } else {
        r["device_id"] = "GPU" + r["pci_slot"];
      }

      // metal_support from system_profiler.
      if (id metal = [item valueForKey:@"spdisplays_mtlgpufamilysupport"]) {
        r["metal_support"] = SQL_TEXT(
            stripPrefix([[metal description] UTF8String], "spdisplays_"));
      }

      results.push_back(r);
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery