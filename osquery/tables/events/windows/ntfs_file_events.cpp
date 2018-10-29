/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <Windows.h>

#include <boost/functional/hash.hpp>

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

  Config::get().files(
      [&path_categories](const std::string& category,
                         const std::vector<std::string>& files) {
        StringList solved_path_list = {};
        for (auto file : files) {
          // NOTE(ww): This will remove nonexistent paths, even if
          // they aren't patterns. For example, C:\foo\bar won't
          // be monitored if it doesn't already exist at table/event
          // creation time. Is that what we want?
          resolveFilePattern(file, solved_path_list);
        }

        path_categories[category] = solved_path_list;
      });

  // List the excluded paths
  std::unordered_map<std::string, StringList> exclude_paths;

  if (json_document.HasMember("exclude_paths")) {
    auto& json_exclude_paths = json_document["exclude_paths"].GetObject();

    for (auto& it : json_exclude_paths) {
      auto category_name = it.name.GetString();
      StringList path_list = {};

      auto& array_object = json_exclude_paths[category_name].GetArray();
      for (const auto& item : array_object) {
        StringList solved_path_list = {};
        resolveFilePattern(item.GetString(), solved_path_list);

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
  const auto& write_paths = d->configuration.write_paths;
  const auto& access_paths = d->configuration.access_paths;
  auto& write_frns = d->configuration.write_frns;
  auto& access_frns = d->configuration.access_frns;

  // TODO(ww): Should we look for FileDeletion events and remove the FRN when
  // we encounter them? Does NTFS recycle FRNs? Does it matter in terms of
  // memory consumption?
  if (isWriteOperation(event.type)) {
    bool frn_found =
        write_frns.find(event.node_ref_number) != write_frns.end() ||
        access_frns.find(event.node_ref_number) != access_frns.end();

    // If this event has an FRN we've marked for monitoring,
    // we emit it.
    if (frn_found) {
      return true;
    }

    // If this event has a parent FRN we've marked for monitoring,
    // we mark it for monitoring as well and emit it.
    // NOTE(ww): This might cause unintuitive behavior when the user specifies
    // a directory to monitor and a file within that directory to exclude --
    // we'll end up monitoring that file anyways, since we're tracking its
    // parent FRN. Maybe just track all excluded files by pathname (at the cost
    // of more memory), and only check that set here?
    if (write_frns.find(event.parent_ref_number) != write_frns.end()) {
      write_frns.insert(event.node_ref_number);
      return true;
    } else if (access_frns.find(event.parent_ref_number) != access_frns.end()) {
      access_frns.insert(event.node_ref_number);
      return true;
    }

    // Otherwise, we haven't seen the FRN or parent FRN before, but
    // the event might have a path that we've marked for monitoring.
    // If so, mark the new FRN for monitoring.
    if (write_paths.find(event.path) != write_paths.end()) {
      write_frns.insert(event.node_ref_number);
      return true;
    }

    if (access_paths.find(event.path) != access_paths.end()) {
      access_frns.insert(event.node_ref_number);
      return true;
    }

    // Finally, the event might have an old path we're interested in.
    // Likewise, mark the FRN for monitoring.
    if (write_paths.find(event.old_path) != write_paths.end()) {
      write_frns.insert(event.node_ref_number);
      return true;
    }

    if (access_paths.find(event.old_path) != access_paths.end()) {
      access_frns.insert(event.node_ref_number);
      return true;
    }

    return false;
  } else {
    // TODO(ww): Why assert here? Does NTFS guarantee that non-write events
    // will never contain an old path?
    assert(event.old_path.empty());

    if (access_frns.find(event.node_ref_number) != access_frns.end()) {
      return true;
    }

    if (access_frns.find(event.parent_ref_number) != access_frns.end()) {
      access_frns.insert(event.node_ref_number);
      return true;
    }

    if (access_paths.find(event.path) != access_paths.end()) {
      access_frns.insert(event.node_ref_number);
      return true;
    }

    return false;
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

  // NOTE(ww): These are emitted in decimal, not hex.
  // There's no good reason for this, other than that
  // boost's mp type doesn't handle std::hex and other
  // ios formatting directives correctly.
  row["node_ref_number"] = TEXT(event.node_ref_number.str());
  row["parent_ref_number"] = TEXT(event.parent_ref_number.str());

  {
    std::stringstream buffer;
    buffer << event.record_timestamp;
    row["record_timestamp"] = TEXT(buffer.str());

    buffer.str("");
    buffer << std::hex << std::setfill('0') << std::setw(16)
           << event.update_sequence_number;
    row["record_usn"] = TEXT(buffer.str());

    // NOTE(ww): Maybe comma-separate here? Pipes make it clear
    // that these are flags, but CSV is easier to parse and is
    // used by other tables.
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
    std::unordered_set<USNFileReferenceNumber> frn_set;

    // Remove excluded paths.
    auto exclude_it = exclude_paths.find(category);
    if (exclude_it != exclude_paths.end()) {
      const auto& excluded_path_list = exclude_it->second;

      // clang-format off
      auto path_erase_it = std::remove_if(
        path_list.begin(),
        path_list.end(),

        [excluded_path_list](const std::string &str) -> bool {
          auto it = std::find(excluded_path_list.begin(), excluded_path_list.end(), str);
          return it != excluded_path_list.end();
        }
      );
      // clang-format on

      if (path_erase_it != path_list.end()) {
        path_list.erase(path_erase_it, path_list.end());
      }
    }

    if (path_list.empty()) {
      continue;
    }

    // Build the FRN set from the now-filtered paths.
    // NOTE(ww): path can be either a file or a directory,
    // so we need to pass FILE_FLAG_BACKUP_SEMANTICS rather
    // than FILE_ATTRIBUTE_NORMAL.
    for (const auto& path : path_list) {
      HANDLE file_hnd = ::CreateFile(path.c_str(),
                                     GENERIC_READ,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     NULL,
                                     OPEN_EXISTING,
                                     FILE_FLAG_BACKUP_SEMANTICS,
                                     NULL);

      // resolveFilePattern should filter out any nonexistent files,
      // so this should never be the case (except for TOCTOU).
      if (file_hnd == INVALID_HANDLE_VALUE) {
        TLOG << "Couldn't open " << path << " while buiding FRN set";
        continue;
      }

      // NOTE(ww): This shouldn't fail once we have a valid handle, but there's
      // another TOCTOU here: another process could delete the file before we
      // get its information. We don't want to lock the file, though, since it
      // could be something imporant used by another process.
      FILE_ID_INFO file_id_info;
      if (!::GetFileInformationByHandleEx(
              file_hnd, FileIdInfo, &file_id_info, sizeof(file_id_info))) {
        TLOG << "Couldn't get FRN for " << path << " while building FRN set";
        ::CloseHandle(file_hnd);
        continue;
      }
      ::CloseHandle(file_hnd);

      const auto& byte_array = file_id_info.FileId.Identifier;
      USNFileReferenceNumber frn;
      boostmp::import_bits(frn,
                           byte_array,
                           byte_array + sizeof(FILE_ID_128::Identifier),
                           0,
                           false);
      frn_set.insert(frn);
    }

    // Save the path and FRN sets.
    std::unordered_set<std::string>* path_destination = nullptr;
    std::unordered_set<USNFileReferenceNumber>* frn_destination = nullptr;
    if (std::find(file_access_categories.begin(),
                  file_access_categories.end(),
                  category) != file_access_categories.end()) {
      path_destination = &configuration.access_paths;
      frn_destination = &configuration.access_frns;
    } else {
      path_destination = &configuration.write_paths;
      frn_destination = &configuration.write_frns;
    }

    for (const auto& path : path_list) {
      path_destination->insert(path);
    }
    for (const auto& frn : frn_set) {
      frn_destination->insert(frn);
    }
  }

  return configuration;
}
} // namespace osquery
