/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "bpfprocesseventstable.h"

#include <osquery/logger/logger.h>
#include <tob/linuxevents/ilinuxevents.h>

namespace osquery {

namespace {

const std::vector<std::tuple<std::string, std::string>> kKnownCgroupPrefixList{
    {"/libpod-conmon-", "podman"},
    {"/libpod-", "podman"},
};

}

struct BPFProcessEventsTable::PrivateData final {
  std::mutex mutex;
  tob::linuxevents::ILinuxEvents::EventList event_list;
};

Expected<BPFProcessEventsTable::Ptr, BPFProcessEventsTable::ErrorCode>
BPFProcessEventsTable::create() {
  try {
    return Ptr(new BPFProcessEventsTable());

  } catch (const std::bad_alloc&) {
    return createError(ErrorCode::MemoryAllocationFailure);

  } catch (const ErrorCode& error_code) {
    return createError(error_code);
  }
}

BPFProcessEventsTable::~BPFProcessEventsTable() {}

const std::string& BPFProcessEventsTable::name() const {
  static const std::string kTableName{"bpf_process_events_v2"};
  return kTableName;
}

void BPFProcessEventsTable::addEvents(
    tob::linuxevents::ILinuxEvents::EventList event_list) {
  std::lock_guard<std::mutex> lock(d->mutex);

  d->event_list.reserve(d->event_list.size() + event_list.size());
  d->event_list.insert(d->event_list.end(),
                       std::make_move_iterator(event_list.begin()),
                       std::make_move_iterator(event_list.end()));
}

BPFProcessEventsTable::BPFProcessEventsTable() : d(new PrivateData) {}

TableColumns BPFProcessEventsTable::columns() const {
  static const TableColumns kColumnList = {
      std::make_tuple("ktime", UNSIGNED_BIGINT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("ppid", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("pid", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("container_name", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("container_backend", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("path", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("argv", TEXT_TYPE, ColumnOptions::DEFAULT),
  };

  return kColumnList;
}

TableRows BPFProcessEventsTable::generate(QueryContext& context) {
  tob::linuxevents::ILinuxEvents::EventList event_list;

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    event_list = std::move(d->event_list);
    d->event_list.clear();
  }

  TableRows row_list;
  std::stringstream buffer;

  for (const auto& event : event_list) {
    auto row = make_table_row();

    row["ktime"] = UNSIGNED_BIGINT(event.ktime);
    row["ppid"] = INTEGER(event.parent_process_id);
    row["pid"] = INTEGER(event.process_id);
    row["cgroup"] = SQL_TEXT(event.cgroup_path);
    row["path"] = event.binary_path;

    buffer.str("");

    for (auto argument_it = event.argument_list.begin();
         argument_it != event.argument_list.end();
         ++argument_it) {
      const auto& argument = *argument_it;

      auto quote_string = (argument.find(' ') != std::string::npos);
      if (quote_string) {
        buffer << "\"";
      }

      for (const auto& c : argument) {
        if (c == '"') {
          buffer << "\\\"";
        } else {
          buffer << c;
        }
      }

      if (quote_string) {
        buffer << "\"";
      }

      if (std::next(argument_it, 1) != event.argument_list.end()) {
        buffer << ", ";
      }
    }

    row["argv"] = buffer.str();

    auto container_name_start{std::string::npos};
    const char* container_backend{nullptr};

    for (const auto& p : kKnownCgroupPrefixList) {
      const auto& prefix = std::get<0>(p);
      const auto& backend = std::get<1>(p);

      auto index = event.cgroup_path.find(prefix);
      if (index != std::string::npos) {
        container_name_start = index + prefix.size();
        container_backend = backend.c_str();

        break;
      }
    }

    if (container_backend != nullptr) {
      row["container_backend"] = SQL_TEXT(container_backend);
    } else {
      row["container_backend"] = SQL_TEXT("");
    }

    if (container_name_start != std::string::npos) {
      auto container_name_end =
          event.cgroup_path.find(".", container_name_start);

      auto container_name_size = container_name_end != std::string::npos
                                     ? container_name_end - container_name_start
                                     : std::string::npos;

      row["container_name"] =
          event.cgroup_path.substr(container_name_start, container_name_size);
    }

    row_list.push_back(std::move(row));
  }

  return row_list;
}

} // namespace osquery