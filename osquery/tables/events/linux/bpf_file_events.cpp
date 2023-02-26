/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/config/config.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/events/linux/bpf_file_events.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/utils/system/uptime.h>

#include <boost/algorithm/string.hpp>
#include <iostream>
#include <regex>

namespace osquery {

REGISTER(BPFFileEventSubscriber, "event_subscriber", "bpf_file_events");

std::vector<std::string> monitored_paths;

void configure_filtering() {
    monitored_paths.clear();

    VLOG(1) << "Configured BPF file event subscriber";
    auto parser = Config::getParser("file_paths");
    if (parser == nullptr) {
        LOG(ERROR) << "No file paths found";
        return;
    }
    auto const& doc = parser->getData().doc();
    auto file_accesses_it = doc.FindMember("file_accesses");
    if (file_accesses_it == doc.MemberEnd()) {
    LOG(ERROR) << "No key 'file_accesses' found when parsing file events"
                    " subscriber configuration.";
    return;
    }
    auto& accesses = file_accesses_it->value;
    if (accesses.GetType() != rapidjson::kArrayType) {
    LOG(ERROR) << "Wrong type found for file_accesses when parsing file events"
                    " subscriber configuration. Found ("
                << accesses.GetType()
                << "),"
                    " expected array ("
                << rapidjson::kArrayType << ").";
    return;
    }

    Config::get().files([&accesses](const std::string& category,
                const std::vector<std::string>& files) {
                for (auto file : files) {
                    replaceGlobWildcards(file);
                    //std::cout << "File pattern: " << file << std::endl;

                    std::vector<std::string> file_path_list = {};
                    resolveFilePattern(file, file_path_list);

                    //for (const auto& file_path : file_path_list) {
                    //    std::cout << "\t File path: " << file_path << std::endl;
                    //}

                    monitored_paths.insert(monitored_paths.end(), file_path_list.begin(), file_path_list.end());
                }
    });
}

void BPFFileEventSubscriber::configure() {
    configure_filtering();
}

Status BPFFileEventSubscriber::init() {
  auto subscription_context = createSubscriptionContext();
  subscribe(&BPFFileEventSubscriber::eventCallback, subscription_context);

  return Status::success();
}

Status BPFFileEventSubscriber::eventCallback(const ECRef& event_context,
                                               const SCRef&) {
  auto row_list = generateRowList(event_context->event_list);
  addBatch(row_list);

  return Status::success();
}

bool BPFFileEventSubscriber::generateRow(
    Row& row, const ISystemStateTracker::Event& event) {
  row = {};

  switch (event.type) {
  case ISystemStateTracker::Event::Type::Open:
    row["syscall"] = TEXT("open");
    break;

  default:
    return false;
  }

  bool is_path_matched = false;

  if (!std::holds_alternative<ISystemStateTracker::Event::FileIOData>(event.data)) {
    row["file_path"] = TEXT("");
    row["flags"] = TEXT("");

    } else {
      const auto& file_io_data =
        std::get<ISystemStateTracker::Event::FileIOData>(event.data);

      row["file_path"] = TEXT(file_io_data.file_path);
      row["flags"] = TEXT(file_io_data.flags);

      if (file_io_data.flags.find("O_CREAT") != std::string::npos)
      {
          configure_filtering();
      }

      for (const auto& match_path : monitored_paths)
      {
          if (boost::algorithm::starts_with(file_io_data.file_path, match_path))
          {
              is_path_matched = true;
              break;
          }
      }
    }

  if (!is_path_matched)
      return false;

  row["ntime"] = TEXT(event.bpf_header.timestamp);
  row["tid"] = INTEGER(event.bpf_header.thread_id);
  row["pid"] = INTEGER(event.bpf_header.process_id);
  row["uid"] = INTEGER(event.bpf_header.user_id);
  row["gid"] = INTEGER(event.bpf_header.group_id);
  row["cid"] = INTEGER(event.bpf_header.cgroup_id);
  row["fd"] = INTEGER(event.bpf_header.exit_code);
  row["probe_error"] = INTEGER(event.bpf_header.probe_error);
  row["parent"] = INTEGER(event.parent_process_id);
  row["path"] = TEXT(event.binary_path);
  row["duration"] = INTEGER(event.bpf_header.duration);
  row["uptime"] = TEXT(std::to_string(getUptime()));

  if (!std::holds_alternative<ISystemStateTracker::Event::FileIOData>(
          event.data)) {
    row["file_path"] = TEXT("");
    row["flags"] = TEXT("");

  } else {
    const auto& file_io_data =
        std::get<ISystemStateTracker::Event::FileIOData>(event.data);

    row["file_path"] = TEXT(file_io_data.file_path);
    row["flags"] = TEXT(file_io_data.flags);
  }

  return true;
}

std::vector<Row> BPFFileEventSubscriber::generateRowList(
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
