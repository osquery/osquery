/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <thread>

#include <boost/process.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/events.h>

namespace osquery {

struct LogEventsSubscriptionContext : public SubscriptionContext {
 public:
 private:
  friend class LogEventsEventPublisher;
};

struct LogEventsEventContext : public EventContext {
 public:
  std::string json_string;
};

using LogEventsEventContextRef = std::shared_ptr<LogEventsEventContext>;
using LogEventsSubscriptionContextRef =
    std::shared_ptr<LogEventsSubscriptionContext>;

class LogEventsEventPublisher
    : public EventPublisher<LogEventsSubscriptionContext,
                            LogEventsEventContext> {
  DECLARE_PUBLISHER("mac_unified_log_events");

 public:
  Status setUp() override;
  void tearDown() override;
  Status run() override;

 private:
  void callback(std::string json_string);
  void stop() override;

  boost::process::child child;
  boost::process::ipstream child_output;
  std::thread reading_thread;

  friend void process_log_stream(LogEventsEventPublisher* publisher);
};

} // namespace osquery
