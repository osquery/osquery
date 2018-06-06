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

#include "osquery/tables/system/posix/xattr_utils.h"

namespace osquery {
bool isSpecialExtendedAttribute(const std::string &name);

bool decodeSpecialExtendedAttribute(ExtendedAttributes& output,
                                      const std::string& path,
                                      const std::string& name);
} // namespace osquery
