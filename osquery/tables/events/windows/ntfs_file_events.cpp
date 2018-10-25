/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>

#include "osquery/core/json.h"
#include "osquery/tables/events/windows/ntfs_file_events.h"

namespace osquery {
REGISTER(NTFSEventSubscriber, "event_subscriber", "ntfs_file_events");

/// Private class data
struct NTFSEventSubscriber::PrivateData final {
  /// Shared data between the publisher and the subscriber
  NTFSEventSubscriptionContextRef subscription_context;

  /// List of paths that must be included or excluded from events
  NTFSFileEventsConfiguration configuration;
};

void NTFSEventSubscriber::readConfiguration() {
  d->configuration = {};

  // List the categories in the file_accesses array
  const auto& json = Config::getParser("file_paths")->getData();
  const auto& json_document = json.doc();

  StringList file_access_categories;
  if (json_document.HasMember("file_accesses")) {
    auto& json_file_accesses = json_document["file_acceses"].GetArray();

    for (const auto& item : json_file_accesses) {
      file_access_categories.push_back(item.GetString());
    }
  }

  // List the paths in file_paths
  std::unordered_map<std::string, StringList> path_categories;

  Config::get().files([&path_categories](
      const std::string& category, const std::vector<std::string>& files) {
    for (auto file : files) {
      // TODO(ww): resolveFilePattern should call this for us.
      // TODO(ww): Are globs the right tool here? I know file_events uses them too,
      // but they don't clearly convey some of the common monitoring patterns:
      //   If I want to monitor a directory, I need two separate patterns: one
      //   for the directory itself, and another to match all children of the
      //   directory. That's unintuitive, and it still doesn't catch the case
      //   where a user creates a new entry under the directory *if* we precompute
      //   the globs.
      replaceGlobWildcards(file);

      StringList solved_path_list = {};
      resolveFilePattern(file, solved_path_list);

      path_categories[category] = solved_path_list;
    }
  });

  // List the excluded paths
  std::unordered_map<std::string, StringList> exclude_paths;

  if (json_document.HasMember("exclude_paths")) {
    auto& json_exclude_paths = json_document["exclude_paths"].GetObject();

    for (auto it = json_exclude_paths.MemberBegin();
         it != json_exclude_paths.MemberEnd();
         ++it) {
      auto category_name = it->name.GetString();
      StringList path_list = {};

      auto& array_object = json_document[category_name].GetArray();
      for (const auto& item : array_object) {
        // Be explicit about the type, we need a writable copy
        // TODO(ww): resolveFilePattern should call this for us.
        std::string path = item.GetString();
        replaceGlobWildcards(path);

        StringList solved_path_list = {};
        resolveFilePattern(path, solved_path_list);

        path_list.insert(path_list.begin(),
                         solved_path_list.begin(),
                         solved_path_list.end());
      }

      exclude_paths.insert({category_name, path_list});
    }
  }

  d->configuration = ProcessConfiguration(
      file_access_categories, path_categories, exclude_paths);
}

bool NTFSEventSubscriber::isWriteOperation(
    const USNJournalEventRecord::Type& type) {
  switch (type) {
  case USNJournalEventRecord::Type::FileWrite:
  case USNJournalEventRecord::Type::DirectoryCreation:
  case USNJournalEventRecord::Type::DirectoryOverwrite:
  case USNJournalEventRecord::Type::FileOverwrite:
  case USNJournalEventRecord::Type::DirectoryTruncation:
  case USNJournalEventRecord::Type::FileTruncation:
  case USNJournalEventRecord::Type::TransactedDirectoryChange:
  case USNJournalEventRecord::Type::TransactedFileChange:
  case USNJournalEventRecord::Type::FileCreation:
  case USNJournalEventRecord::Type::DirectoryDeletion:
  case USNJournalEventRecord::Type::FileDeletion:
  case USNJournalEventRecord::Type::DirectoryLinkChange:
  case USNJournalEventRecord::Type::FileLinkChange:
  case USNJournalEventRecord::Type::DirectoryRename_NewName:
  case USNJournalEventRecord::Type::FileRename_NewName:
    return true;

  default:
    return false;
  }
}

bool NTFSEventSubscriber::shouldEmit(const NTFSEventRecord& event) {
  const auto& write_monitored_path_list =
      d->configuration.write_monitored_path_list;
  const auto& access_monitored_path_list =
      d->configuration.access_monitored_path_list;

  if (isWriteOperation(event.type)) {
    auto it = std::find(write_monitored_path_list.begin(),
                        write_monitored_path_list.end(),
                        event.path);

    auto it2 = std::find(access_monitored_path_list.begin(),
                         access_monitored_path_list.end(),
                         event.path);

    if (it != write_monitored_path_list.end() ||
        it2 != access_monitored_path_list.end()) {
      return true;
    }

    it = std::find(write_monitored_path_list.begin(),
                   write_monitored_path_list.end(),
                   event.old_path);

    it2 = std::find(access_monitored_path_list.begin(),
                    access_monitored_path_list.end(),
                    event.old_path);

    if (it != write_monitored_path_list.end() ||
        it2 != access_monitored_path_list.end()) {
      return true;
    }

    return false;

  } else {
    assert(event.old_path.empty());

    auto it = std::find(access_monitored_path_list.begin(),
                        access_monitored_path_list.end(),
                        event.path);

    return it != access_monitored_path_list.end();
  }
}

Row NTFSEventSubscriber::generateRowFromEvent(const NTFSEventRecord& event) {
  Row row;

  auto action_description_it = kNTFSEventToStringMap.find(event.type);
  assert(action_description_it != kNTFSEventToStringMap.end());

  row["action"] = TEXT(action_description_it->second);
  row["old_path"] = TEXT(event.old_path);
  row["path"] = TEXT(event.path);
  row["partial"] = INTEGER(event.partial);

  {
    std::stringstream buffer;
    buffer << event.record_timestamp;
    row["record_timestamp"] = TEXT(buffer.str());

    buffer.str("");
    buffer << std::hex << std::setfill('0') << std::setw(16)
           << event.update_sequence_number;
    row["record_usn"] = TEXT(buffer.str());

    buffer.str("");
    bool add_separator = false;
    for (const auto& p : kWindowsFileAttributeMap) {
      const auto& bit = p.first;
      const auto& label = p.second;

      if ((event.attributes & bit) == 0) {
        continue;
      }

      if (add_separator) {
        buffer << " | ";
      }

      buffer << label;
      add_separator = true;
    }

    row["file_attributes"] = TEXT(buffer.str());
  }

  std::string drive_letter(1, event.drive_letter);
  row["drive_letter"] = TEXT(drive_letter);

  return row;
}

NTFSEventSubscriber::NTFSEventSubscriber() : d(new PrivateData) {}

NTFSEventSubscriber::~NTFSEventSubscriber() {}

Status NTFSEventSubscriber::init() {
  d->subscription_context = createSubscriptionContext();
  subscribe(&NTFSEventSubscriber::Callback, d->subscription_context);

  return Status(0);
}

void NTFSEventSubscriber::configure() {
  readConfiguration();
}

Status NTFSEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  std::vector<Row> emitted_row_list;

  for (const auto& event : ec->event_list) {
    if (!shouldEmit(event)) {
      continue;
    }

    auto row = generateRowFromEvent(event);
    emitted_row_list.push_back(row);
  }

  if (!emitted_row_list.empty()) {
    addBatch(emitted_row_list);
  }

  return Status(0);
}

// TODO(alessandro): Write a test for this
NTFSFileEventsConfiguration ProcessConfiguration(
    const StringList& file_access_categories,
    std::unordered_map<std::string, StringList> path_categories,
    const std::unordered_map<std::string, StringList>& exclude_paths) {
  NTFSFileEventsConfiguration configuration = {};

  for (auto& path_category : path_categories) {
    auto& category = path_category.first;
    auto& path_list = path_category.second;

    // Remove excluded paths
    auto exclude_it = exclude_paths.find(category);
    if (exclude_it != exclude_paths.end()) {
      const auto& excluded_path_list = exclude_it->second;

      // clang-format off
      auto erase_it = std::remove_if(
        path_list.begin(),
        path_list.end(),

        [excluded_path_list](const std::string &str) -> bool {
          auto it = std::find(excluded_path_list.begin(), excluded_path_list.end(), str);
          return it != excluded_path_list.end();
        }
      );
      // clang-format on

      if (erase_it != path_list.end()) {
        path_list.erase(erase_it, path_list.end());
      }
    }

    if (path_list.empty()) {
      continue;
    }

    // Save the path list
    std::unordered_set<std::string>* destination = nullptr;
    if (std::find(file_access_categories.begin(),
                  file_access_categories.end(),
                  category) != file_access_categories.end()) {
      destination = &configuration.access_monitored_path_list;
    } else {
      destination = &configuration.write_monitored_path_list;
    }

    for (const auto& path : path_list) {
      destination->insert(path);
    }
  }

  return configuration;
}
} // namespace osquery
