/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iomanip>
#include <sstream>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <boost/algorithm/string.hpp>

#include <osquery/tables.h>

#include "osquery/core/darwin/iokit.hpp"
#include "osquery/tables/system/smbios_utils.h"

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
                              size_t size) {
      genSMBIOSTable(index, hdr, address, size, results);
    }));
  }
  return results;
}

QueryData genMemoryDevices(QueryContext& context) {
  QueryData results;

  DarwinSMBIOSParser parser;
  if (!parser.discover()) {
    return results;
  }

  parser.tables([&results](size_t index,
                           const SMBStructHeader* hdr,
                           uint8_t* address,
                           size_t size) {
    genSMBIOSMemoryDevices(index, hdr, address, size, results);
  });

  return results;
}

QueryData genPlatformInfo(QueryContext& context) {
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
}
}
