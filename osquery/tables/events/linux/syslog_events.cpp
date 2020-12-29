/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/events/linux/syslog.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/events/event_utils.h>

namespace osquery {

FLAG(uint64,
     syslog_events_expiry,
     60 * 60 * 24 * 30, // Keep 30 days by default
     "Timeout to expire event subscriber results");

FLAG(uint64,
     syslog_events_max,
     100000,
     "Maximum number of events per type to buffer");

class SyslogEventSubscriber : public EventSubscriber<SyslogEventPublisher> {
 public:
  // Implement the pure virtual init interface.
  Status init() override {
    SyslogSubscriptionContextRef sc = createSubscriptionContext();
    subscribe(&SyslogEventSubscriber::Callback, sc);
    return Status::success();
  }

  size_t getEventsExpiry() override {
    return FLAGS_syslog_events_expiry;
  }

  size_t getEventBatchesMax() override {
    return FLAGS_syslog_events_max;
  }

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(SyslogEventSubscriber, "event_subscriber", "syslog_events");

Status SyslogEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r(ec->fields);
  add(r);
  return Status::success();
}
}
