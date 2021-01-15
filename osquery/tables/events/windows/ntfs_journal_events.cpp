/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

/* NOTE(woodruffw): osquery targets Windows 7, but we do feature-testing below
 * to support journal events on later versions of Windows.
 */
#undef _WIN32_WINNT
#undef NTDDI_VERSION

#include <SdkDdkVer.h>
#include <Windows.h>

#include <boost/functional/hash.hpp>

#include <osquery/config/config.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/events/windows/ntfs_journal_events.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/json/json.h>

namespace osquery {
REGISTER(NTFSEventSubscriber, "event_subscriber", "ntfs_journal_events");

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

bool NTFSEventSubscriber::shouldEmit(const SCRef& sc,
                                     const NTFSEventRecord& event) {
  const auto& write_paths = sc->write_paths;
  const auto& access_paths = sc->access_paths;
  auto& write_frns = sc->write_frns;
  auto& access_frns = sc->access_frns;

  // TODO(woodruffw): Should we look for FileDeletion events and remove the FRN
  // when we encounter them? Does NTFS recycle FRNs? Does it matter in terms of
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
    // NOTE(woodruffw): This might cause unintuitive behavior when the user
    // specifies a directory to monitor and a file within that directory to
    // exclude -- we'll end up monitoring that file anyways, since we're
    // tracking its parent FRN. Maybe just track all excluded files by pathname
    // (at the cost of more memory), and only check that set here?
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
    // TODO(woodruffw): Why assert here? Does NTFS guarantee that non-write
    // events will never contain an old path?
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

  row["action"] = SQL_TEXT(action_description_it->second);
  row["old_path"] = SQL_TEXT(event.old_path);
  row["path"] = SQL_TEXT(event.path);
  row["partial"] = INTEGER(event.partial);

  // NOTE(woodruffw): These are emitted in decimal, not hex.
  // There's no good reason for this, other than that
  // boost's mp type doesn't handle std::hex and other
  // ios formatting directives correctly.
  row["node_ref_number"] = SQL_TEXT(event.node_ref_number.str());
  row["parent_ref_number"] = SQL_TEXT(event.parent_ref_number.str());

  {
    std::stringstream buffer;
    buffer << event.record_timestamp;
    row["record_timestamp"] = SQL_TEXT(buffer.str());

    buffer.str("");
    buffer << std::hex << std::setfill('0') << std::setw(16)
           << event.update_sequence_number;
    row["record_usn"] = SQL_TEXT(buffer.str());

    // NOTE(woodruffw): Maybe comma-separate here? Pipes make it clear
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

    row["file_attributes"] = SQL_TEXT(buffer.str());
  }

  std::string drive_letter(1, event.drive_letter);
  row["drive_letter"] = SQL_TEXT(drive_letter);

  return row;
}

NTFSEventSubscriber::NTFSEventSubscriber() {}

NTFSEventSubscriber::~NTFSEventSubscriber() {}

Status NTFSEventSubscriber::init() {
  return Status::success();
}

void NTFSEventSubscriber::configure() {
  // List the categories in the file_accesses array
  const auto& json = Config::getParser("file_paths")->getData();
  const auto& json_document = json.doc();

  StringList access_categories;
  if (json_document.HasMember("file_accesses") &&
      json_document["file_accesses"].IsArray()) {
    auto& json_file_accesses = json_document["file_accesses"].GetArray();

    for (const auto& item : json_file_accesses) {
      if (!item.IsString()) {
        continue;
      }
      access_categories.push_back(item.GetString());
    }
  }

  Config::get().files(
      [this, &json_document, &access_categories](
          const std::string& category, const std::vector<std::string>& files) {
        StringList include_path_list = {};
        for (const auto& file : files) {
          // NOTE(woodruffw): This will remove nonexistent paths, even if
          // they aren't patterns. For example, C:\foo\bar won't
          // be monitored if it doesn't already exist at table/event
          // creation time. Is that what we want?
          resolveFilePattern(file, include_path_list);
        }

        StringList exclude_path_list = {};

        if (json_document.HasMember("exclude_paths") &&
            json_document["exclude_paths"][category].IsArray()) {
          const auto& excludes =
              json_document["exclude_paths"][category].GetArray();
          for (const auto& exclude : excludes) {
            if (!exclude.IsString()) {
              continue;
            }
            resolveFilePattern(exclude.GetString(), exclude_path_list);
          }
        }

        auto sc = createSubscriptionContext();

        sc->category = category;
        processConfiguration(
            sc, access_categories, include_path_list, exclude_path_list);

        subscribe(&NTFSEventSubscriber::Callback, sc);
      });
}

Status NTFSEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  std::vector<Row> emitted_row_list;

  for (const auto& event : ec->event_list) {
    if (!shouldEmit(sc, event)) {
      continue;
    }

    auto row = generateRowFromEvent(event);
    row["category"] = SQL_TEXT(sc->category);
    emitted_row_list.push_back(row);
  }

  addBatch(emitted_row_list);

  return Status::success();
}

void processConfiguration(const NTFSEventSubscriptionContextRef context,
                          const StringList& access_categories,
                          StringList& include_paths,
                          StringList& exclude_paths) {
  // clang-format off
  auto path_erase_it = std::remove_if(
    include_paths.begin(),
    include_paths.end(),

    [exclude_paths](const std::string &str) -> bool {
      auto it = std::find(exclude_paths.begin(), exclude_paths.end(), str);
      return it != exclude_paths.end();
    }
  );
  // clang-format on

  if (path_erase_it != include_paths.end()) {
    include_paths.erase(path_erase_it, include_paths.end());
  }

  if (include_paths.empty()) {
    return;
  }

  std::unordered_set<USNFileReferenceNumber> frn_set;

  // Build the FRN set from the now-filtered paths.
  // NOTE(woodruffw): path can be either a file or a directory,
  // so we need to pass FILE_FLAG_BACKUP_SEMANTICS rather
  // than FILE_ATTRIBUTE_NORMAL.
  for (const auto& path : include_paths) {
    HANDLE file_hnd = ::CreateFile(stringToWstring(path).c_str(),
                                   GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL,
                                   OPEN_EXISTING,
                                   FILE_FLAG_BACKUP_SEMANTICS,
                                   NULL);

    // resolveFilePattern should filter out any nonexistent files,
    // so this should never be the case (except for TOCTOU).
    if (file_hnd == INVALID_HANDLE_VALUE) {
      TLOG << "Couldn't open " << path << " while building FRN set";
      continue;
    }

    // NOTE(woodruffw): This shouldn't fail once we have a valid handle, but
    // there's another TOCTOU here: another process could delete the file before
    // we get its information. We don't want to lock the file, though, since it
    // could be something important used by another process.
    USNFileReferenceNumber frn{};

#if _WIN32_WINNT > _WIN32_WINNT_WIN7
    FILE_ID_INFO file_id_info;
    if (!::GetFileInformationByHandleEx(
            file_hnd, FileIdInfo, &file_id_info, sizeof(file_id_info))) {
      TLOG << "Couldn't get FRN for " << path << " while building FRN set";
      ::CloseHandle(file_hnd);
      continue;
    }

    frn = file_id_info.FileId;
#else
    BY_HANDLE_FILE_INFORMATION file_id_info;
    if (!::GetFileInformationByHandle(file_hnd, &file_id_info)) {
      TLOG << "Couldn't get FRN for " << path << " while building FRN set";
      ::CloseHandle(file_hnd);
      continue;
    }

    frn = (static_cast<DWORDLONG>(file_id_info.nFileIndexHigh) << 32) |
          file_id_info.nFileIndexLow;
#endif

    ::CloseHandle(file_hnd);
    frn_set.insert(frn);
  }

  // Save the path and FRN sets.
  std::unordered_set<std::string>* path_destination = nullptr;
  std::unordered_set<USNFileReferenceNumber>* frn_destination = nullptr;
  if (std::find(access_categories.begin(),
                access_categories.end(),
                context->category) != access_categories.end()) {
    path_destination = &context->access_paths;
    frn_destination = &context->access_frns;
  } else {
    path_destination = &context->write_paths;
    frn_destination = &context->write_frns;
  }

  for (const auto& path : include_paths) {
    path_destination->insert(path);
  }
  for (const auto& frn : frn_set) {
    frn_destination->insert(frn);
  }
}
} // namespace osquery
