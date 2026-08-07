/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/linux/bpf/bpf_process_event_publisher.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/events/linux/bpf_process_events.h>

#include <boost/algorithm/string.hpp>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

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

bool BPFProcessEventSubscriber::generateRow(Row& row,
                                            const BPFProcessEvent& event) {
  row = {};

  // Filter out failed exec syscalls (negative exit codes indicate errors)
  auto signed_exit_code = static_cast<std::int64_t>(event.exit_code);
  if (signed_exit_code < 0) {
    return false;
  }

  row["ntime"] = SQL_TEXT(event.timestamp);
  row["tid"] = INTEGER(event.tid);
  row["pid"] = INTEGER(event.pid);
  row["parent"] = INTEGER(event.ppid);
  row["uid"] = INTEGER(event.uid);
  row["gid"] = INTEGER(event.gid);
  row["cid"] = INTEGER(event.cgroup_id);
  row["exit_code"] = SQL_TEXT(std::to_string(event.exit_code));
  row["probe_error"] = INTEGER(event.probe_error);
  row["syscall"] = SQL_TEXT("execve");
  row["path"] = SQL_TEXT(event.path);
  row["cwd"] = SQL_TEXT(event.cwd);
  row["duration"] = INTEGER(event.duration);

  // Generate cmdline columns
  row["cmdline"] = generateCmdlineColumn(event.args);
  row["json_cmdline"] = generateJsonCmdlineColumn(event.args);

  return true;
}

std::vector<Row> BPFProcessEventSubscriber::generateRowList(
    const BPFProcessEventList& event_list) {
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
    const std::string& args) {
  // Args are already space-separated from BPF program
  // Just clean up any trailing spaces
  std::string result = args;
  boost::trim(result);
  return result;
}

std::string BPFProcessEventSubscriber::generateJsonCmdlineColumn(
    const std::string& args) {
  // Parse space-separated args into JSON array
  std::vector<std::string> argv;
  boost::split(argv, args, boost::is_any_of(" "), boost::token_compress_on);

  // Remove empty strings
  argv.erase(std::remove_if(argv.begin(),
                            argv.end(),
                            [](const std::string& s) { return s.empty(); }),
             argv.end());

  // Create JSON array
  rapidjson::Document doc;
  doc.SetArray();
  auto& allocator = doc.GetAllocator();

  for (const auto& arg : argv) {
    rapidjson::Value val;
    val.SetString(arg.c_str(), arg.length(), allocator);
    doc.PushBack(val, allocator);
  }

  // Serialize to string
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  doc.Accept(writer);

  return buffer.GetString();
}

} // namespace osquery
