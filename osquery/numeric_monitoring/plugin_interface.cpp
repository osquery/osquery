/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/numeric_monitoring/plugin_interface.h>
#include <osquery/plugin.h>
#include <osquery/registry_factory.h>

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
  return keys;
};

} // namespace

const RecordKeys& recordKeys() {
  static const auto keys = createRecordKeys();
  return keys;
}

} // namespace monitoring

Status NumericMonitoringPlugin::call(const PluginRequest& request,
                                     PluginResponse& response) {
  // should be implemented in plugins
  return Status();
}

} // namespace osquery
