/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/experimental/events_stream/events_stream.h>
#include <osquery/experimental/events_stream/events_stream_registry.h>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

#include <boost/io/detail/quoted_manip.hpp>

namespace osquery {

DEFINE_string(events_streaming_plugin,
              "",
              "Experimental events streaming plugin");

namespace events {

void dispatchSerializedEvent(const std::string& serialized_event) {
  if (FLAGS_events_streaming_plugin.empty()) {
    LOG(INFO) << "New event: " << serialized_event;
    return;
  }
  auto status = Registry::call(streamRegistryName(),
                               FLAGS_events_streaming_plugin,
                               {
                                   {"event", serialized_event},
                               });
  if (!status.ok()) {
    LOG(ERROR) << "Data loss. Event " << boost::io::quoted(serialized_event)
               << " dispatch failed because " << status.what();
  }
}

} // namespace events
} // namespace osquery
