/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iomanip>
#include <sstream>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <osquery/core.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

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
  IOKitPCIProperties(const std::string& compatible);
};

inline void idToHex(std::string& id) {
  long base = 0;
  // = AS_LITERAL(int, id);
  if (safeStrtol(id, 10, base)) {
    std::stringstream hex_id;
    hex_id << std::hex << std::setw(4) << std::setfill('0') << (base & 0xFFFF);
    id = hex_id.str();
  }
}

std::string getIOKitProperty(const CFMutableDictionaryRef& details,
                             const std::string& key);
}
}
