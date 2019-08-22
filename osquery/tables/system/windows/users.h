/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/core.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

std::string getUserHomeDir(const std::string& sid);

} // namespace tables
} // namespace osquery
