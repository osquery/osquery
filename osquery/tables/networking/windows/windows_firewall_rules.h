/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>
#include <vector>

#include <netfw.h>

namespace osquery {
namespace tables {

struct FirewallRule {
  std::string name;
  std::string appName;
  NET_FW_ACTION action;
  bool enabled;
  NET_FW_RULE_DIRECTION direction;
  long protocol;
  std::string localAddresses;
  std::string remoteAddresses;
  std::string localPorts;
  std::string remotePorts;
  std::string icmpTypesCodes;
  long profileBitmask;
};

using FirewallRules = std::vector<FirewallRule>;

} // namespace tables
} // namespace osquery