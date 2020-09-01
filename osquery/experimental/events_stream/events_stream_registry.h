/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/plugins/plugin.h>
#include <osquery/core/query.h>
#include <osquery/utils/expected/expected.h>

#include <osquery/numeric_monitoring/numeric_monitoring.h>

namespace osquery {

class EventsStreamPlugin : public Plugin {
 public:
  Status call(const PluginRequest& request, PluginResponse& response) override;
};

namespace events {

char const* streamRegistryName();

} // namespace events
} // namespace osquery
