/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/plugins/plugin.h>
#include <osquery/registry_factory.h>

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
