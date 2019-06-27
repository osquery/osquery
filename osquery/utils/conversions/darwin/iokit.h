/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>
#include <CoreServices/CoreServices.h>

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

void idToHex(std::string& id);

} // namespace osquery
