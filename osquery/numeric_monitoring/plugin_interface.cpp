/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/plugins/plugin.h>
#include <osquery/registry/registry_factory.h>

#include "osquery/numeric_monitoring/plugin_interface.h"

namespace osquery {

CREATE_REGISTRY(NumericMonitoringPlugin, monitoring::registryName());

namespace monitoring {

const char* registryName() {
  static const auto name = "numeric_monitoring";
  return name;
}

namespace {

RecordKeys createRecordKeys() {
  auto keys = RecordKeys{};
  keys.path = "path";
  keys.value = "value";
  keys.timestamp = "timestamp";
  keys.pre_aggregation = "pre_aggregation";
  keys.sync = "sync";
  return keys;
};

HostIdentifierKeys createHostIdentifierKeys() {
  auto keys = HostIdentifierKeys{};
  keys.name = "<DEVICE_NAME>";
  keys.scheme = "<DEVICE_HOSTNAME_SCHEME>";
  return keys;
};

} // namespace

const RecordKeys& recordKeys() {
  static const auto keys = createRecordKeys();
  return keys;
}

const HostIdentifierKeys& hostIdentifierKeys() {
  static const auto keys = createHostIdentifierKeys();
  return keys;
}

} // namespace monitoring

Status NumericMonitoringPlugin::call(const PluginRequest& request,
                                     PluginResponse& response) {
  // should be implemented in plugins
  return Status::success();
}

} // namespace osquery
