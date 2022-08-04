/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sys/sysctl.h>
#include <sys/types.h>

#include <array>
#include <iostream>
#include <memory>

#include <osquery/logger/logger.h>
#include <osquery/tables/system/darwin/smbios_utils.h>
#include <osquery/utils/conversions/darwin/cfdata.h>
#include <osquery/utils/conversions/darwin/cfnumber.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/conversions/darwin/iokit.h>
#include <osquery/utils/darwin/iokit_helpers.h>

namespace osquery {
namespace tables {

namespace {
const char* kPowerManagerDevice = "pmgr";
const char* kCpusDevice = "cpus";
const char* kPCoresVoltageStates = "voltage-states5-sram";
const char* kPCoresCount = "p-core-count";
const char* kECoresCount = "e-core-count";
} // namespace

QueryData genIntelCpuInfo(QueryContext& context) {
  QueryData results;

  DarwinSMBIOSParser parser;
  if (!parser.discover()) {
    VLOG(1) << "Failed to discover SMBIOS entry point";
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSProcessor(index, hdr, address, textAddrs, size, results);
  });

  // Decorate table
  std::int32_t device_id = 0;
  for (auto& row : results) {
    auto current_processor_id = row.find("processor_type");
    if (current_processor_id == row.end()) {
      continue;
    }

    // `device_id` column is not part of the SMBios table.
    auto friendly_name =
        kSMBIOSProcessorTypeFriendlyName.find(current_processor_id->second);
    if (friendly_name != kSMBIOSProcessorTypeFriendlyName.end()) {
      row["device_id"] = friendly_name->second + std::to_string(device_id++);
    }
  }

  return results;
}

std::optional<std::uint32_t> getAarch64MaxCPUFreq() {
  auto matching = IOServiceMatching(kAppleARMIODeviceClassName_.data());
  if (matching == nullptr) {
    VLOG(1) << "No matching " << kAppleARMIODeviceClassName_;
    // No devices matched AppleARMIODevice.
    return std::nullopt;
  }

  io_iterator_t device_it;

  auto kr =
      IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &device_it);

  if (kr != KERN_SUCCESS) {
    VLOG(1) << "Failed to get matching " << kAppleARMIODeviceClassName_;
    return std::nullopt;
  }

  UniqueIoIterator device_it_ptr(device_it);
  UniqueIoService device_ptr;

  std::uint32_t max_freq = 0;

  while ((device_ptr = UniqueIoService(IOIteratorNext(device_it_ptr.get())))
             .get()) {
    io_name_t buf;
    kr = IORegistryEntryGetName(device_ptr.get(), buf);

    if (kr != KERN_SUCCESS) {
      VLOG(1) << "Failed to get one of the " << kAppleARMIODeviceClassName_
              << " name";
      continue;
    }

    std::string name(buf);

    if (name != kPowerManagerDevice) {
      continue;
    }

    CFMutableDictionaryRef properties;
    kr = IORegistryEntryCreateCFProperties(
        device_ptr.get(), &properties, kCFAllocatorDefault, kNilOptions);

    if (kr != KERN_SUCCESS) {
      LOG(ERROR) << "Failed to create and retrieve the power manager "
                    "properties dictionary";
      return std::nullopt;
    }

    UniqueCFMutableDictionaryRef properties_ptr(properties);

    // voltage-states5-sram contains the performance cores available frequencies
    auto cfkey = UniqueCFStringRef(CFStringCreateWithCString(
        kCFAllocatorDefault, kPCoresVoltageStates, kCFStringEncodingUTF8));
    auto p_cores_freq_property = static_cast<CFDataRef>(
        CFDictionaryGetValue(properties_ptr.get(), cfkey.get()));

    if (p_cores_freq_property == nullptr) {
      VLOG(1) << "Failed to retrieve the power manager property "
              << kPCoresVoltageStates;
      return std::nullopt;
    }

    auto p_cores_freq_type = CFGetTypeID(p_cores_freq_property);
    if (p_cores_freq_type != CFDataGetTypeID()) {
      VLOG(1) << "Unsupported data type for the " << kPCoresVoltageStates
              << " property";
      return std::nullopt;
    }

    std::size_t length = CFDataGetLength(p_cores_freq_property);

    // The frequencies are in hz, saved in an array
    // as little endian 4 byte integers
    for (std::size_t i = 0; i < length - 3; i += 4) {
      std::uint32_t cur_freq = 0;
      CFDataGetBytes(p_cores_freq_property,
                     CFRangeMake(i, sizeof(uint32_t)),
                     reinterpret_cast<UInt8*>(&cur_freq));

      if (max_freq < cur_freq) {
        max_freq = cur_freq;
      }
    }
  }

  return max_freq;
}

std::optional<std::pair<std::string, std::string>> getHybridCoresNumber() {
  auto matching = IOServiceMatching(kIOPlatformDeviceClassName_.data());
  if (matching == nullptr) {
    VLOG(1) << "No matching " << kIOPlatformDeviceClassName_;
    // No devices matched IOPlatformDevice.
    return std::nullopt;
  }

  io_iterator_t device_it;
  auto kr =
      IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &device_it);

  if (kr != KERN_SUCCESS) {
    VLOG(1) << "Failed to get matching " << kIOPlatformDeviceClassName_;
    return std::nullopt;
  }

  UniqueIoIterator device_it_ptr(device_it);
  UniqueIoService device_ptr;

  std::pair<std::string, std::string> hybrid_cores_counts{};

  while ((device_ptr = UniqueIoService(IOIteratorNext(device_it))).get()) {
    io_name_t buf;
    kr = IORegistryEntryGetName(device_ptr.get(), buf);

    if (kr != KERN_SUCCESS) {
      VLOG(1) << "Failed to get one of the " << kIOPlatformDeviceClassName_
              << " name";
      continue;
    }

    std::string name(buf);

    if (name != kCpusDevice) {
      continue;
    }

    CFMutableDictionaryRef properties;
    kr = IORegistryEntryCreateCFProperties(
        device_ptr.get(), &properties, kCFAllocatorDefault, kNilOptions);

    if (kr != KERN_SUCCESS) {
      LOG(ERROR) << "Failed to create and retrieve the power manager "
                    "properties dictionary";
      return std::nullopt;
    }

    UniqueCFMutableDictionaryRef properties_ptr(properties);

    auto e_core_count_key = UniqueCFStringRef(CFStringCreateWithCString(
        kCFAllocatorDefault, kECoresCount, kCFStringEncodingUTF8));
    auto p_core_count_key = UniqueCFStringRef(CFStringCreateWithCString(
        kCFAllocatorDefault, kPCoresCount, kCFStringEncodingUTF8));

    auto e_core_count_property = static_cast<CFDataRef>(
        CFDictionaryGetValue(properties_ptr.get(), e_core_count_key.get()));
    auto p_core_count_property = static_cast<CFDataRef>(
        CFDictionaryGetValue(properties_ptr.get(), p_core_count_key.get()));

    if (e_core_count_property == nullptr || p_core_count_property == nullptr) {
      return std::nullopt;
    }

    auto e_core_count_type = CFGetTypeID(e_core_count_property);
    if (e_core_count_type != CFDataGetTypeID()) {
      VLOG(1) << "Unsupported data type for the " << kECoresCount
              << " property. Found: " << e_core_count_type;
      return std::nullopt;
    }

    auto p_core_count_type = CFGetTypeID(p_core_count_property);
    if (p_core_count_type != CFDataGetTypeID()) {
      VLOG(1) << "Unsupported data type for the " << kPCoresCount
              << " property. Found: " << p_core_count_type;
      return std::nullopt;
    }

    auto data_to_uint32_string = [](CFDataRef data) -> std::string {
      std::uint32_t value;
      CFDataGetBytes(data, CFRangeMake(0, sizeof(uint32_t)), (UInt8*)&value);
      return std::to_string(value);
    };

    hybrid_cores_counts.first = data_to_uint32_string(e_core_count_property);
    hybrid_cores_counts.second = data_to_uint32_string(p_core_count_property);

    return hybrid_cores_counts;
  }

  return std::nullopt;
}

QueryData genAarch64CpuInfo(QueryContext& context) {
  QueryData rows;
  Row r;

  // Hardcoded for now, we only support a single CPU
  r["device_id"] = "CPU0";

  std::array<char, 256> brand_string;

  // Leave space for a null-terminator
  size_t len = sizeof(brand_string) - 1;
  auto res =
      sysctlbyname("machdep.cpu.brand_string", &brand_string, &len, nullptr, 0);

  if (res == 0) {
    r["model"] = TEXT(brand_string.data());
  }
  r["manufacturer"] = "Apple";
  r["processor_type"] = INTEGER(3); // 3 = Central Processor
  r["address_width"] = INTEGER(64);

  std::uint32_t sysctl_value = 0;
  len = sizeof(sysctl_value);
  res = sysctlbyname("machdep.cpu.core_count", &sysctl_value, &len, nullptr, 0);

  if (res == 0) {
    r["number_of_cores"] = INTEGER(sysctl_value);
  }

  len = sizeof(sysctl_value);
  res = sysctlbyname("hw.logicalcpu", &sysctl_value, &len, nullptr, 0);

  if (res == 0) {
    r["logical_processors"] = INTEGER(sysctl_value);
  }

  auto opt_max_freq = getAarch64MaxCPUFreq();
  if (opt_max_freq.has_value()) {
    r["max_clock_speed"] = INTEGER(*opt_max_freq / (1000 * 1000));
  }

  auto opt_hybrid_cores_number = getHybridCoresNumber();

  if (opt_hybrid_cores_number.has_value()) {
    const auto& [ecores_number, pcores_number] = *opt_hybrid_cores_number;
    r["number_of_efficiency_cores"] = INTEGER(ecores_number);
    r["number_of_performance_cores"] = INTEGER(pcores_number);
  }

  rows.emplace_back(std::move(r));

  return rows;
}

QueryData genCpuInfo(QueryContext& context) {
#ifdef __aarch64__
  return genAarch64CpuInfo(context);
#else
  return genIntelCpuInfo(context);
#endif
}
} // namespace tables
} // namespace osquery
