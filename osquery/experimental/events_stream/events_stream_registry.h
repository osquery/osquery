/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/plugins/plugin.h>
#include <osquery/query.h>
#include <osquery/utils/expected/expected.h>

#include <osquery/numeric_monitoring.h>

namespace osquery {

class EventsStreamPlugin : public Plugin {
 public:
  Status call(const PluginRequest& request, PluginResponse& response) override;
};

namespace events {

char const* streamRegistryName();

} // namespace events
} // namespace osquery
