/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/system/linux/udev.h>

namespace osquery {

std::string getUdevValue(struct udev_device* device,
                         const std::string& property) {
  auto value = udev_device_get_property_value(device, property.c_str());
  if (value != nullptr) {
    return std::string(value);
  }
  return "";
}

std::string getUdevAttr(struct udev_device* device, const std::string& attr) {
  auto value = udev_device_get_sysattr_value(device, attr.c_str());
  if (value != nullptr) {
    return std::string(value);
  }
  return "";
}
} // namespace osquery
