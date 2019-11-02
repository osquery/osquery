/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <libudev.h>

#include <string>

namespace osquery {
/**
 * @brief Return a string representation of a udev property.
 *
 * @param device the udev device pointer.
 * @param property the udev property identifier string.
 * @return string representation of the property or empty if null.
 */
std::string getUdevValue(struct udev_device* device,
                         const std::string& property);

/**
 * @brief Return a string representation of a udev system attribute.
 *
 * @param device the udev device pointer.
 * @param property the udev system attribute identifier string.
 * @return string representation of the attribute or empty if null.
 */
std::string getUdevAttr(struct udev_device* device, const std::string& attr);
} // namespace osquery
