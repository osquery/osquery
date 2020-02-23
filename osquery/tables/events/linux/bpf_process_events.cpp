/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <asm/unistd_64.h>

#include <osquery/events/linux/bpfprocesseventspublisher.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>
#include <osquery/tables/events/linux/bpf_process_events.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {
REGISTER(BPFProcessEventsSubscriber, "event_subscriber", "bpf_process_events");

Status BPFProcessEventsSubscriber::init() {
  auto subscription_context = createSubscriptionContext();
  subscribe(&BPFProcessEventsSubscriber::eventCallback, subscription_context);

  return Status::success();
}

Status BPFProcessEventsSubscriber::eventCallback(
    const ECRef& event_context, const SCRef& subscription_context) {
  static_cast<void>(subscription_context);

  std::vector<Row> row_list;
  for (const auto& event : event_context->event_list) {
    Row row = {};

    row["timestamp"] = INTEGER(event.timestamp);
    row["pid"] = INTEGER(event.process_id);
    row["tid"] = INTEGER(event.thread_id);
    row["uid"] = INTEGER(event.user_id);
    row["gid"] = INTEGER(event.group_id);
    row["exit"] = INTEGER(event.exit_code);
    row["probe_error"] = INTEGER(event.probe_error);
    row["syscall"] = TEXT(event.syscall_name);
    row["executable"] = TEXT(event.executable_path);
    row["cmdline"] = TEXT(event.cmdline);

    row_list.push_back(std::move(row));
  }

  if (!row_list.empty()) {
    addBatch(row_list);
  }

  return Status::success();
}
} // namespace osquery
