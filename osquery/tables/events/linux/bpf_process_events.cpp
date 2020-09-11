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
#include <osquery/tables/events/linux/bpf_process_events.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {
REGISTER(BPFEventSubscriber, "event_subscriber", "bpf_process_events");

Status BPFEventSubscriber::init() {
  auto subscription_context = createSubscriptionContext();
  subscribe(&BPFEventSubscriber::eventCallback, subscription_context);

  return Status::success();
}

Status BPFEventSubscriber::eventCallback(const ECRef& event_context,
                                         const SCRef&) {
  auto row_list = generateRowList(event_context->event_list);
  addBatch(row_list);

  return Status::success();
}

bool BPFEventSubscriber::generateRow(Row& row,
                                     const ISystemStateTracker::Event& event) {
  row = {};

  row["timestamp"] = TEXT(event.bpf_header.timestamp);
  row["thread_id"] = INTEGER(event.bpf_header.thread_id);
  row["process_id"] = INTEGER(event.bpf_header.process_id);
  row["uid"] = INTEGER(event.bpf_header.user_id);
  row["gid"] = INTEGER(event.bpf_header.group_id);
  row["cgroup_id"] = INTEGER(event.bpf_header.cgroup_id);
  row["exit_code"] = TEXT(std::to_string(event.bpf_header.exit_code));
  row["probe_error"] = INTEGER(event.bpf_header.probe_error);

  if (event.type == ISystemStateTracker::Event::Type::Exec) {
    row["syscall"] = TEXT("exec");

    if (!std::holds_alternative<ISystemStateTracker::Event::ExecData>(
            event.data)) {
      VLOG(1) << "Missing ExecData in Exec event";

    } else {
      const auto& exec_data =
          std::get<ISystemStateTracker::Event::ExecData>(event.data);

      std::stringstream buffer;
      for (auto param_it = exec_data.argv.begin();
           param_it != exec_data.argv.end();
           ++param_it) {
        // TODO(alessandro): correcly escape characters
        const auto& parameter = *param_it;
        buffer << "\"" << parameter << "\"";

        if (std::next(param_it, 1) != exec_data.argv.end()) {
          buffer << " ";
        }
      }

      row["cmdline"] = buffer.str();
    }

  } else if (event.type == ISystemStateTracker::Event::Type::Fork) {
    row["syscall"] = TEXT("fork");
    row["cmdline"] = TEXT("");

  } else {
    return false;
  }

  row["parent_process_id"] = INTEGER(event.parent_process_id);
  row["binary_path"] = TEXT(event.binary_path);
  row["cwd"] = TEXT(event.cwd);

  return true;
}

std::vector<Row> BPFEventSubscriber::generateRowList(
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
