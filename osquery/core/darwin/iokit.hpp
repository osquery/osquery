/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <atomic>
#include <iomanip>

#include <CoreServices/CoreServices.h>
#include <IOKit/IOKitLib.h>

#include <osquery/status.h>

#include "osquery/core/conversions.h"

namespace osquery {

extern const std::string kIOUSBDeviceClassName_;
extern const std::string kIOPCIDeviceClassName_;
extern const std::string kIOPlatformExpertDeviceClassName_;
extern const std::string kIOACPIPlatformDeviceClassName_;
extern const std::string kIOPlatformDeviceClassname_;

struct IOKitPCIProperties {
  std::string vendor_id;
  std::string model_id;
  std::string pci_class;
  std::string driver;

  /// Populate IOKit PCI device properties from the "compatible" property.
  explicit IOKitPCIProperties(const std::string& compatible);
};

std::string getIOKitProperty(const CFMutableDictionaryRef& details,
                             const std::string& key);
long long int getNumIOKitProperty(const CFMutableDictionaryRef& details,
                                  const std::string& key);

inline void idToHex(std::string& id) {
  auto const base_exp = tryTo<long>(id, 10);
  if (base_exp.isValue()) {
    std::stringstream hex_id;
    hex_id << std::hex << std::setw(4) << std::setfill('0')
           << (base_exp.get() & 0xFFFF);
    id = hex_id.str();
  }
}

} // namespace osquery
