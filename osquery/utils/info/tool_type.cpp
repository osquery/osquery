/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
