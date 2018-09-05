/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/tables.h>

#include "osquery/events/darwin/log_events.h"

namespace pt = boost::property_tree;

const std::string FIELD_NAMES[] = {"category",
                                   "activityID",
                                   "eventType",
                                   "processImageUUID",
                                   "processUniqueID",
                                   "threadID",
                                   "timestamp",
                                   "traceID",
                                   "messageType",
                                   "senderProgramCounter",
                                   "processID",
                                   "machTimestamp",
                                   "timezoneName",
                                   "subsystem",
                                   "eventMessage",
                                   "senderImageUUID",
                                   "processImagePath",
                                   "senderImagePath"};

namespace osquery {

class LogEventSubscriber : public EventSubscriber<LogEventsEventPublisher> {
 public:
  Status init() override;

  Status Callback(const LogEventsEventContextRef& ec,
                  const LogEventsSubscriptionContextRef& sc);
};

REGISTER(LogEventSubscriber, "event_subscriber", "darwin_unified_log_events");

Status LogEventSubscriber::init() {
  auto subscription = createSubscriptionContext();
  subscribe(&LogEventSubscriber::Callback, subscription);

  return Status(0, "OK");
}

Status LogEventSubscriber::Callback(const LogEventsEventContextRef& ec,
                                    const LogEventsSubscriptionContextRef& sc) {
  Row r;

  pt::ptree t;
  std::stringstream str(ec->json_string);
  try {
    pt::read_json(str, t);
    for (auto field : FIELD_NAMES) {
      r[field] = t.get<std::string>(field, "");
    }
    add(r);
  } catch (std::exception& e) {
    LOG(ERROR) << "Exception while parsing log event: " << e.what();
  }

  return Status(0, "OK");
}
} // namespace osquery
