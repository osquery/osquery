/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/info/tool_type.h>

namespace osquery {

/**
 * Unknown before something sets it.
 *
 * For tests this should be set in the gtest main.
 */
ToolType kToolType{ToolType::UNKNOWN};
} // namespace osquery
