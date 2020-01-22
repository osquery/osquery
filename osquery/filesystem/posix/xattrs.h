/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
