/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>
#include <sstream>

#include <sys/sysctl.h>
#include <sys/types.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <osquery/core/tables.h>
#include <osquery/tables/system/smbios_utils.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/conversions/darwin/iokit.h>
#include <osquery/utils/conversions/join.h>

namespace osquery {
namespace tables {

#define kIOSMBIOSClassName_ "AppleSMBIOS"
#define kIOSMBIOSPropertyName_ "SMBIOS"
#define kIOSMBIOSEPSPropertyName_ "SMBIOS-EPS"

class DarwinSMBIOSParser : public SMBIOSParser {
 public:
  void setData(uint8_t* tables, size_t length) {
    table_data_ = tables;
    table_size_ = length;
  }

  bool discover();

  ~DarwinSMBIOSParser() {
    if (smbios_data_ != nullptr) {
      free(smbios_data_);
    }
  }

 private:
  uint8_t* smbios_data_{nullptr};
};

bool DarwinSMBIOSParser::discover() {
  auto matching = IOServiceMatching(kIOSMBIOSClassName_);
  if (matching == nullptr) {
    // No ACPI platform expert service found.
    return false;
  }

  auto service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
  if (service == 0) {
    return false;
  }

  // Unlike ACPI the SMBIOS property will return several structures
  // followed by a table of structured entries (also called tables).
  // http://dmtf.org/sites/default/files/standards/documents/DSP0134_2.8.0.pdf
  CFTypeRef smbios = IORegistryEntryCreateCFProperty(
      service, CFSTR(kIOSMBIOSPropertyName_), kCFAllocatorDefault, 0);
  if (smbios == nullptr) {
    IOObjectRelease(service);
    return false;
  }

  // Check the first few SMBIOS structures before iterating through tables.
  const uint8_t* smbios_data = CFDataGetBytePtr((CFDataRef)smbios);
  size_t length = CFDataGetLength((CFDataRef)smbios);

  if (smbios_data == nullptr || length == 0) {
    // Problem creating SMBIOS property.
    CFRelease(smbios);
    IOObjectRelease(service);
    return false;
  }

  smbios_data_ = (uint8_t*)malloc(length);
  if (smbios_data_ != nullptr) {
    memcpy(smbios_data_, smbios_data, length);
  }
  IOObjectRelease(service);
  CFRelease(smbios);

  // The property and service exist.
  setData(const_cast<uint8_t*>(smbios_data_), length);
  return (smbios_data_ != nullptr);
}

QueryData genSMBIOSTables(QueryContext& context) {
  QueryData results;

  // Parse structures.
  DarwinSMBIOSParser parser;
  if (parser.discover()) {
    parser.tables(([&results](size_t index,
                              const SMBStructHeader* hdr,
                              uint8_t* address,
                              uint8_t* textAddrs,
                              size_t size) {
      genSMBIOSTable(index, hdr, address, size, results);
    }));
  }
  return results;
}

QueryData genAarch64MemoryDevices(QueryContext& context) {
  Row r;
  auto chosen =
      IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
  if (chosen != 0) {
    CFMutableDictionaryRef details = nullptr;
    IORegistryEntryCreateCFProperties(
        chosen, &details, kCFAllocatorDefault, kNilOptions);
    IOObjectRelease(chosen);
    r["memory_type"] = getIOKitProperty(details, "dram-type");
  }

  uint64_t memsize;
  size_t len = sizeof(memsize);
  sysctlbyname("hw.memsize", &memsize, &len, NULL, 0);
  r["size"] = INTEGER(memsize / 1048576);

  return {r};
}

QueryData genIntelMemoryDevices(QueryContext& context) {
  QueryData results;

  DarwinSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSMemoryDevices(index, hdr, address, textAddrs, size, results);
  });

  return results;
}

QueryData genMemoryDevices(QueryContext& context) {
#ifdef __aarch64__
  return genAarch64MemoryDevices(context);
#else
  return genIntelMemoryDevices(context);
#endif
}

QueryData genMemoryArrays(QueryContext& context) {
  QueryData results;

  DarwinSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSMemoryArrays(index, hdr, address, size, results);
  });

  return results;
}

QueryData genMemoryArrayMappedAddresses(QueryContext& context) {
  QueryData results;

  DarwinSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSMemoryArrayMappedAddresses(index, hdr, address, size, results);
  });

  return results;
}

QueryData genMemoryErrorInfo(QueryContext& context) {
  QueryData results;

  DarwinSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSMemoryErrorInfo(index, hdr, address, size, results);
  });

  return results;
}

QueryData genMemoryDeviceMappedAddresses(QueryContext& context) {
  QueryData results;

  DarwinSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSMemoryDeviceMappedAddresses(index, hdr, address, size, results);
  });

  return results;
}

QueryData genOEMStrings(QueryContext& context) {
  QueryData results;

  DarwinSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           uint8_t* textAddrs,
                           size_t size) {
    genSMBIOSOEMStrings(hdr, address, textAddrs, size, results);
  });

  return results;
}

QueryData genIntelPlatformInfo(QueryContext& context) {
  auto rom = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/rom");
  if (rom == 0) {
    return {};
  }

  CFMutableDictionaryRef details = nullptr;
  IORegistryEntryCreateCFProperties(
      rom, &details, kCFAllocatorDefault, kNilOptions);
  IOObjectRelease(rom);

  // Success is determined by the details dictionary existence.
  if (details == nullptr) {
    return {};
  }

  Row r;
  r["vendor"] = getIOKitProperty(details, "vendor");
  r["volume_size"] = getIOKitProperty(details, "fv-main-size");
  r["size"] = getIOKitProperty(details, "rom-size");
  r["date"] = getIOKitProperty(details, "release-date");
  r["version"] = getIOKitProperty(details, "version");

  {
    auto address = getIOKitProperty(details, "fv-main-address");
    if (!address.empty()) {
      auto value = boost::lexical_cast<size_t>(address);

      std::stringstream hex_id;
      hex_id << std::hex << std::setw(8) << std::setfill('0') << value;
      r["address"] = "0x" + hex_id.str();
    } else {
      r["address"] = "0x0";
    }
  }

  {
    std::vector<std::string> extra_items;
    auto info = getIOKitProperty(details, "apple-rom-info");
    std::vector<std::string> info_lines;
    iter_split(info_lines, info, boost::algorithm::first_finder("%0a"));
    for (const auto& line : info_lines) {
      std::vector<std::string> details_vec;
      iter_split(details_vec, line, boost::algorithm::first_finder(": "));
      if (details_vec.size() > 1) {
        boost::trim(details_vec[1]);
        if (details_vec[0].find("Revision") != std::string::npos) {
          r["revision"] = details_vec[1];
        }
        extra_items.push_back(details_vec[1]);
      }
    }
    r["extra"] = osquery::join(extra_items, "; ");
  }

  CFRelease(details);
  return {r};
}

QueryData genAarch64PlatformInfo(QueryContext& context) {
  auto device_tree =
      IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/");
  if (device_tree == 0) {
    return {};
  }

  CFMutableDictionaryRef details = nullptr;
  IORegistryEntryCreateCFProperties(
      device_tree, &details, kCFAllocatorDefault, kNilOptions);
  IOObjectRelease(device_tree);

  if (details == nullptr) {
    return {};
  }
  Row r;
  r["vendor"] = getIOKitProperty(details, "manufacturer");

  auto chosen =
      IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
  if (chosen != 0) {
    IORegistryEntryCreateCFProperties(
        chosen, &details, kCFAllocatorDefault, kNilOptions);
    IOObjectRelease(chosen);
    r["version"] = getIOKitProperty(details, "system-firmware-version");
  }

  auto root = IORegistryGetRootEntry(kIOMasterPortDefault);
  if (root != 0) {
    CFTypeRef property = (CFDataRef)IORegistryEntryCreateCFProperty(
        root, CFSTR(kIOKitBuildVersionKey), kCFAllocatorDefault, 0);
    if (property != nullptr) {
      auto signature = stringFromCFString((CFStringRef)property);
      CFRelease(property);
      r["extra"] = signature;
    }
  }

  // Unavailable on M1 Macs
  r["volume_size"] = "";
  r["size"] = "";
  r["date"] = "";
  r["revision"] = "";
  r["address"] = "";

  CFRelease(details);
  return {r};
}

QueryData genPlatformInfo(QueryContext& context) {
#ifdef __aarch64__
  return genAarch64PlatformInfo(context);
#else
  return genIntelPlatformInfo(context);
#endif
}
} // namespace tables
} // namespace osquery
