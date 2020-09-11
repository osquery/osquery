/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

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
  std::stringstream cmdline;

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

    // Since the BPF tracer copies memory regions, the string buffers may
    // contain many unused bytes after the null terminator. Make sure we stop
    // early by using c_str()

    row["binary_path"] = TEXT(event.binary_path.c_str());

    cmdline.str("");

    for (auto arg_it = event.argument_list.begin() + 1;
         arg_it < event.argument_list.end();
         ++arg_it) {
      const auto& arg = *arg_it;
      cmdline << arg.c_str();

      if (std::next(arg_it, 1) != event.argument_list.end()) {
        cmdline << " ";
      }
    }

    row["cmdline"] = TEXT(cmdline.str());
    row_list.push_back(std::move(row));
  }

  if (!row_list.empty()) {
    addBatch(row_list);
  }

  return Status::success();
}
} // namespace osquery
