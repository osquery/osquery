/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/events/linux/bpfsocketeventspublisher.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>
#include <osquery/tables/events/linux/bpf_socket_events.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {
REGISTER(BPFSocketEventsSubscriber, "event_subscriber", "bpf_socket_events");

Status BPFSocketEventsSubscriber::init() {
  auto subscription_context = createSubscriptionContext();
  subscribe(&BPFSocketEventsSubscriber::eventCallback, subscription_context);

  return Status::success();
}

Status BPFSocketEventsSubscriber::eventCallback(
    const ECRef& event_context, const SCRef& subscription_context) {
  static_cast<void>(subscription_context);

  std::vector<Row> row_list;
  for (const auto& event : event_context->event_list) {
    Row row = {};

    row["timestamp"] = TEXT(event.timestamp);
    row["thread_id"] = INTEGER(event.thread_id);
    row["process_id"] = INTEGER(event.process_id);
    row["uid"] = INTEGER(event.user_id);
    row["gid"] = INTEGER(event.group_id);
    row["cgroup_id"] = INTEGER(event.cgroup_id);
    row["exit_code"] = INTEGER(event.exit_code);
    row["probe_error"] = INTEGER(event.probe_error);
    row["syscall"] = TEXT(event.syscall_name);

    row["binary_path"] = TEXT(event.binary_path);
    row["address_family"] = TEXT(event.address_family);

    row["local_address"] = TEXT(event.local_address);
    row["local_port"] = INTEGER(event.local_port);

    row["remote_address"] = TEXT(event.remote_address);
    row["remote_port"] = INTEGER(event.remote_port);

    row_list.push_back(std::move(row));
  }

  if (!row_list.empty()) {
    addBatch(row_list);
  }

  return Status::success();
}
} // namespace osquery
