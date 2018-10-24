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

#include <osquery/core.h>
#include <osquery/distributed.h>
#include <osquery/enroll.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>

namespace osquery {

Status MockDistributedSetReadValue(const std::string value) {
  PluginResponse response;
  Status status =
      Registry::call("distributed",
                     {{"action", "setMockReadValue"}, {"value", value}},
                     response);
  return status;
}

Status MockDistributedGetWrites(std::vector<std::string>& dest) {
  PluginResponse response = PluginResponse();
  Status status =
      Registry::call("distributed", {{"action", "getMockWrites"}}, response);
  if (status.ok() == false) {
    return status;
  }

  for (auto it = response[0].begin(); it != response[0].end(); it++) {
    auto key = it->first;
    if (key.size() > 2 && key[0] == 'W' && key[1] == '_') {
      dest.push_back(it->second);
    }
  }

  return status;
}

Status MockDistributedClearWrites() {
  PluginResponse response = PluginResponse();
  Status status =
      Registry::call("distributed", {{"action", "clearMockWrites"}}, response);
  return status;
}

Status MockDistributedWriteEndpointEnabled(bool isEnabled) {
  PluginResponse response = PluginResponse();
  Status status = Registry::call(
      "distributed",
      {{"action", "setMockWriteStatus"}, {"value", (isEnabled ? "1" : "0")}},
      response);
  return status;
}

Status MockDistributedReadEndpointEnabled(bool isEnabled) {
  PluginResponse response = PluginResponse();
  Status status = Registry::call(
      "distributed",
      {{"action", "setMockReadStatus"}, {"value", (isEnabled ? "1" : "0")}},
      response);
  return status;
}

} // namespace osquery
