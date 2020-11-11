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
#include <osquery/tables/events/linux/bpf_process_events.h>

#include <boost/algorithm/string.hpp>
#include <rapidjson/document.h>

namespace osquery {

REGISTER(BPFProcessEventSubscriber, "event_subscriber", "bpf_process_events");

Status BPFProcessEventSubscriber::init() {
  auto subscription_context = createSubscriptionContext();
  subscribe(&BPFProcessEventSubscriber::eventCallback, subscription_context);

  return Status::success();
}

Status BPFProcessEventSubscriber::eventCallback(const ECRef& event_context,
                                                const SCRef&) {
  auto row_list = generateRowList(event_context->event_list);
  addBatch(row_list);

  return Status::success();
}

bool BPFProcessEventSubscriber::generateRow(
    Row& row, const ISystemStateTracker::Event& event) {
  row = {};

  if (event.type != ISystemStateTracker::Event::Type::Exec) {
    return false;
  }

  auto signed_exit_code = static_cast<std::int64_t>(event.bpf_header.exit_code);
  if (signed_exit_code >= -EHWPOISON && signed_exit_code <= -EPERM) {
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
  row["syscall"] = TEXT("exec");
  row["parent"] = INTEGER(event.parent_process_id);
  row["path"] = TEXT(event.binary_path);
  row["cwd"] = TEXT(event.cwd);
  row["duration"] = INTEGER(event.bpf_header.duration);

  if (!std::holds_alternative<ISystemStateTracker::Event::ExecData>(
          event.data)) {
    VLOG(1) << "Missing ExecData in Exec event";

    row["cmdline"] = "";
    row["json_cmdline"] = "[]";

  } else {
    const auto& exec_data =
        std::get<ISystemStateTracker::Event::ExecData>(event.data);

    row["cmdline"] = generateCmdlineColumn(exec_data.argv);
    row["json_cmdline"] = generateJsonCmdlineColumn(exec_data.argv);
  }

  return true;
}

std::vector<Row> BPFProcessEventSubscriber::generateRowList(
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

std::string BPFProcessEventSubscriber::generateCmdlineColumn(
    const std::vector<std::string>& argv) {
  std::string output;

  for (auto param_it = argv.begin(); param_it != argv.end(); ++param_it) {
    const auto& arg = *param_it;

    // clang-format off
    auto whitespace_it = std::find_if(
      arg.begin(),
      arg.end(),
      
      [](const char &c) -> bool {
        return std::isspace(c);
      }
    );
    // clang-format on

    if (whitespace_it != arg.end()) {
      output += '\'';
    }

    output += arg;

    if (whitespace_it != arg.end()) {
      output += '\'';
    }

    if (std::next(param_it, 1) != argv.end()) {
      output += ' ';
    }
  }

  return output;
}

std::string BPFProcessEventSubscriber::generateJsonCmdlineColumn(
    const std::vector<std::string>& argv) {
  rapidjson::Document document;
  document.SetArray();

  auto& allocator = document.GetAllocator();
  for (const auto& arg : argv) {
    rapidjson::Value value = {};
    value.SetString(arg, allocator);

    document.PushBack(value, allocator);
  }

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

  document.Accept(writer);
  return buffer.GetString();
}

} // namespace osquery
