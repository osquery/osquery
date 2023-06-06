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

#include <boost/optional/optional.hpp>
#include <osquery/utils/expected/expected.h>

namespace osquery {

enum class XAttrFileError { NoLength, List, SizeChanged };
enum class XAttrValueError { NoLength, Get, SizeChanged };
enum class XAttrGetError { GenericError, NoFile };

using ExtendedAttributeValue = std::vector<std::uint8_t>;

using ExtendedAttributeMap =
    std::unordered_map<std::string, ExtendedAttributeValue>;

using XAttrGetResult = Expected<ExtendedAttributeMap, XAttrGetError>;
using XAttrNameListResult = Expected<std::vector<std::string>, XAttrFileError>;
using XAttrValueResult = Expected<ExtendedAttributeValue, XAttrValueError>;

std::string xAttrFileErrorToString(XAttrFileError error,
                                   const std::string& path);
std::string xAttrValueErrorToString(XAttrValueError error,
                                    const std::string& path,
                                    const std::string& name);

XAttrNameListResult getExtendedAttributesNames(int fd);
XAttrValueResult getExtendedAttributeValue(int fd, const std::string& name);
XAttrGetResult getExtendedAttributes(const std::string& path);

} // namespace osquery
