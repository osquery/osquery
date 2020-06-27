/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/info/tool_type.h>

namespace osquery {

namespace {

/// Current tool type.
ToolType kToolType{ToolType::UNKNOWN};

} // namespace

void setToolType(ToolType tool) {
  kToolType = tool;
}

ToolType getToolType() {
  return kToolType;
}

bool isDaemon() {
  return kToolType == ToolType::DAEMON;
}

bool isShell() {
  return kToolType == ToolType::SHELL;
}
} // namespace osquery
