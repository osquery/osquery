/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <osquery/utils/status/status.h>

namespace osquery {
using ExtendedAttributeValue = std::vector<std::uint8_t>;

using ExtendedAttributeMap =
    std::unordered_map<std::string, ExtendedAttributeValue>;

Status getExtendedAttributes(ExtendedAttributeMap& xattr_map,
                             const std::string& path);
} // namespace osquery
