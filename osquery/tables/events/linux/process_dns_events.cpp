/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <asm/unistd_64.h>

#include <osquery/events/linux/processdnseventspublisher.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>
#include <osquery/tables/events/linux/process_dns_events.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {
REGISTER(ProcessDNSEventsSubscriber, "event_subscriber", "process_dns_events");

Status ProcessDNSEventsSubscriber::init() {
  auto sc = createSubscriptionContext();
  subscribe(&ProcessDNSEventsSubscriber::Callback, sc);

  return Status::success();
}

Status ProcessDNSEventsSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  std::vector<Row> row_list;

  for (const auto& event : ec->event_list) {
    Row row = {};
    row["timestamp"] = INTEGER(event.timestamp);
    row["user_id"] = INTEGER(event.user_id);
    row["group_id"] = INTEGER(event.group_id);
    row["process_id"] = INTEGER(event.process_id);
    row["thread_id"] = INTEGER(event.thread_id);
    row["node"] = TEXT(event.node);
    row["service"] = TEXT(event.service);
    row["exit_code"] = INTEGER(event.exit_code);

    row_list.push_back(std::move(row));
  }

  if (!row_list.empty()) {
    addBatch(row_list);
  }

  return Status::success();
}
} // namespace osquery
