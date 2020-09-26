/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/events/linux/bpf_socket_events.h>

namespace osquery {
REGISTER(BPFSocketEventSubscriber, "event_subscriber", "bpf_socket_events");

Status BPFSocketEventSubscriber::init() {
  auto subscription_context = createSubscriptionContext();
  subscribe(&BPFSocketEventSubscriber::eventCallback, subscription_context);

  return Status::success();
}

Status BPFSocketEventSubscriber::eventCallback(const ECRef& event_context,
                                         const SCRef&) {
  auto row_list = generateRowList(event_context->event_list);
  addBatch(row_list);

  return Status::success();
}

bool BPFSocketEventSubscriber::generateRow(Row& row,
                                     const ISystemStateTracker::Event& event) {
  row = {};

  if (event.type != ISystemStateTracker::Event::Type::Exec) {
    return false;
  }

  switch (event.type) {
  case ISystemStateTracker::Event::Type::Connect:
    row["syscall"] = TEXT("connect");
    break;

  case ISystemStateTracker::Event::Type::Bind:
    row["syscall"] = TEXT("bind");
    break;

  case ISystemStateTracker::Event::Type::Listen:
    row["syscall"] = TEXT("listen");
    break;

  case ISystemStateTracker::Event::Type::Accept:
    row["syscall"] = TEXT("accept");
    break;

  default:
    return false;
  }

  row["timestamp"] = TEXT(event.bpf_header.timestamp);
  row["thread_id"] = INTEGER(event.bpf_header.thread_id);
  row["process_id"] = INTEGER(event.bpf_header.process_id);
  row["uid"] = INTEGER(event.bpf_header.user_id);
  row["gid"] = INTEGER(event.bpf_header.group_id);
  row["cgroup_id"] = INTEGER(event.bpf_header.cgroup_id);
  row["exit_code"] = TEXT(std::to_string(event.bpf_header.exit_code));
  row["probe_error"] = INTEGER(event.bpf_header.probe_error);
  row["parent_process_id"] = INTEGER(event.parent_process_id);
  row["path"] = TEXT(event.binary_path);

  // Column("fd", TEXT, "The file description for the process socket"),
  // Column("family", INTEGER, "The Internet protocol family ID"),
  // Column("type", INTEGER, "The socket type"),
  // Column("protocol", INTEGER, "The network protocol ID", 
  // Column("local_address", TEXT, "Local address associated with socket"),
  // Column("remote_address", TEXT, "Remote address associated with socket"),
  // Column("local_port", INTEGER, "Local network protocol port number"),
  // Column("remote_port", INTEGER, "Remote network protocol port number"),

  return true;
}

std::vector<Row> BPFSocketEventSubscriber::generateRowList(
    const ISystemStateTracker::EventList& event_list) {
  std::vector<Row> row_list;

  for (const auto& event : event_list) {
    Row row = {};
    if (generateRow(row, event)) {
      row_list.push_back(std::move(row));
    }
  }

  return row_list;
}
} // namespace osquery
