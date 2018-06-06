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

#ifdef __APPLE__
#include <TargetConditionals.h>

#ifdef TARGET_OS_MAC
#include "osquery/tables/system/darwin/xattr_utils.h"
#else
#error Unsupported macOS target
#endif
#endif

#include <osquery/tables.h>

namespace osquery {
using ExtendedAttributeList = std::vector<std::pair<std::string, std::string>>;

bool isSpecialExtendedAttribute(const std::string& name);

Status expandSpecialExtendedAttribute(ExtendedAttributeList& output,
                                      const std::string& path,
                                      const std::string& name);

Status getAllExtendedAttributes(ExtendedAttributeList& attributes,
                                const std::string& path);
} // namespace osquery
