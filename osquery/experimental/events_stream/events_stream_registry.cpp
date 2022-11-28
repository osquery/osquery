/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/experimental/events_stream/events_stream_registry.h>

#include <boost/io/quoted.hpp>

#include <osquery/registry/registry_factory.h>

namespace osquery {

CREATE_REGISTRY(EventsStreamPlugin, events::streamRegistryName());

Status EventsStreamPlugin::call(const PluginRequest& request,
                                PluginResponse& response) {
  // should be implemented in plugins
  return Status::success();
}

namespace events {

char const* streamRegistryName() {
  return "osquery_events_stream";
}

} // namespace events
} // namespace osquery
