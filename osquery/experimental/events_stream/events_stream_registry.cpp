/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/experimental/events_stream/events_stream_registry.h>

#include <boost/io/detail/quoted_manip.hpp>

#include <osquery/registry_factory.h>

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
