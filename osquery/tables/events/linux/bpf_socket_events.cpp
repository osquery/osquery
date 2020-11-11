/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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

bool BPFSocketEventSubscriber::generateRow(
    Row& row, const ISystemStateTracker::Event& event) {
  row = {};

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

  row["ntime"] = TEXT(event.bpf_header.timestamp);
  row["tid"] = INTEGER(event.bpf_header.thread_id);
  row["pid"] = INTEGER(event.bpf_header.process_id);
  row["uid"] = INTEGER(event.bpf_header.user_id);
  row["gid"] = INTEGER(event.bpf_header.group_id);
  row["cid"] = INTEGER(event.bpf_header.cgroup_id);
  row["exit_code"] = TEXT(std::to_string(event.bpf_header.exit_code));
  row["probe_error"] = INTEGER(event.bpf_header.probe_error);
  row["parent"] = INTEGER(event.parent_process_id);
  row["path"] = TEXT(event.binary_path);
  row["duration"] = INTEGER(event.bpf_header.duration);

  if (!std::holds_alternative<ISystemStateTracker::Event::SocketData>(
          event.data)) {
    row["fd"] = TEXT("");
    row["family"] = INTEGER(-1);
    row["type"] = INTEGER(-1);
    row["protocol"] = INTEGER(-1);
    row["local_address"] = TEXT("");
    row["remote_address"] = TEXT("");
    row["local_port"] = INTEGER(0);
    row["remote_port"] = INTEGER(0);

  } else {
    const auto& socket_data =
        std::get<ISystemStateTracker::Event::SocketData>(event.data);

    row["fd"] = INTEGER(socket_data.fd);
    row["family"] = INTEGER(socket_data.domain);
    row["type"] = INTEGER(socket_data.type);
    row["protocol"] = INTEGER(socket_data.protocol);
    row["local_address"] = TEXT(socket_data.local_address);
    row["remote_address"] = TEXT(socket_data.remote_address);
    row["local_port"] = INTEGER(socket_data.local_port);
    row["remote_port"] = INTEGER(socket_data.remote_port);
  }

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
