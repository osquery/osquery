/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <map>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include <boost/functional/hash.hpp>

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/core/conversions.h"
#include "osquery/core/utils.h"
#include "osquery/events/windows/ntfs_event_publisher.h"

namespace osquery {
FLAG(bool,
     enable_ntfs_event_publisher,
     false,
     "Enables the NTFS event publiser");

/// This debug flag will print the incoming events
HIDDEN_FLAG(bool,
            ntfs_event_publisher_debug,
            false,
            "Debug the NTFS event publisher");

REGISTER(NTFSEventPublisher, "event_publisher", "ntfseventspublisher");

namespace fs = boost::filesystem;

namespace {
/// This structure is used for the internal components cache
struct NodeReferenceInfo final {
  USNFileReferenceNumber parent;
  std::string name;
};
}

struct NTFSEventPublisher::PrivateData final {
  /// Each reader service instance is mapped to the drive letter it is
  /// reading from
  std::unordered_map<char, USNJournalReaderInstance> reader_service_map;

  /// This mutex protects the reader_service_map
  Mutex reader_service_map_mutex;

  /// This map contains a cache of the last file id -> path resolutions. It is
  /// ordered so that we can clear the oldest entries first when limiting the
  /// maximum amount of entries
  std::map<USNFileReferenceNumber, std::string> path_resolution_cache;

  /// The volume handle map contains a cache of the drive handles
  std::unordered_map<char, HANDLE> drive_handle_map;

  /// This mutex protects the drive handle map
  Mutex drive_handle_map_mutex;

  /// This cache contains a mapping from ref id to file name (without the full
  /// path). We can gather this data passively by just inspecting the journal
  /// records
  std::unordered_map<USNFileReferenceNumber, NodeReferenceInfo>
      path_components_cache;
};

void NTFSEventPublisher::restartJournalReaderServices(
    std::unordered_set<char>& active_drives) {
  WriteLock lock(d->reader_service_map_mutex);

  // Spawn new services
  for (const auto& drive_letter : active_drives) {
    if (d->reader_service_map.find(drive_letter) !=
        d->reader_service_map.end()) {
      continue;
    }

    auto context = std::make_shared<USNJournalReaderContext>();
    context->drive_letter = drive_letter;

    VLOG(1) << "Creating a new USNJournalReader service for drive "
            << static_cast<char>(::toupper(drive_letter)) << ":";

    auto service = std::make_shared<USNJournalReader>(context);

    d->reader_service_map.insert(
        {drive_letter, std::make_pair(service, context)});

    Dispatcher::addService(service);
  }

  // Terminate the ones we no longer need
  for (auto service_it = d->reader_service_map.begin();
       service_it != d->reader_service_map.end();) {
    const auto& drive_letter = service_it->first;
    if (active_drives.count(drive_letter)) {
      service_it++;
      continue;
    }

    const auto& service_instance = service_it->second;
    const auto& service_context = service_instance.second;

    VLOG(1) << "Terminating the USNJournalReader service assigned to drive "
            << static_cast<char>(::toupper(drive_letter)) << ":";

    service_context->terminate = true;
    service_it = d->reader_service_map.erase(service_it);
  }
}

std::vector<USNJournalEventRecord> NTFSEventPublisher::acquireEvents() {
  ReadLock lock(d->reader_service_map_mutex);

  // We have a reader service for each volume; attempt to fetch data
  // from each one of them
  std::vector<USNJournalEventRecord> record_list;

  for (auto& reader_info : d->reader_service_map) {
    auto& reader_instance = reader_info.second;
    auto& reader_context = reader_instance.second;

    std::vector<USNJournalEventRecord> new_record_list = {};

    {
      std::unique_lock<std::mutex> lock(
          reader_context->processed_records_mutex);

      auto wait_status = reader_context->processed_records_cv.wait_for(
          lock, std::chrono::seconds(1));

      if (wait_status == std::cv_status::no_timeout) {
        new_record_list = std::move(reader_context->processed_record_list);
        reader_context->processed_record_list.clear();
      }
    }

    record_list.reserve(record_list.size() + new_record_list.size());

    std::move(new_record_list.begin(),
              new_record_list.end(),
              std::back_inserter(record_list));

    new_record_list.clear();
  }

  return record_list;
}

void NTFSEventPublisher::updatePathComponentCache(
    const std::vector<USNJournalEventRecord>& event_list) {
  for (const auto& event : event_list) {
    if (d->path_components_cache.find(event.node_ref_number) !=
        d->path_components_cache.end()) {
      continue;
    }

    NodeReferenceInfo node_ref_info = {};
    node_ref_info.parent = event.parent_ref_number;
    node_ref_info.name = event.name;

    d->path_components_cache.insert({event.node_ref_number, node_ref_info});
  }

  if (d->path_components_cache.size() >= 20000U) {
    auto range_start = d->path_components_cache.begin();
    auto range_end = std::next(range_start, 10000U);

    d->path_components_cache.erase(range_start, range_end);
  }
}

void NTFSEventPublisher::takeEventsAndNotifySuscribers(
    std::vector<USNJournalEventRecord>& event_list) {
  if (event_list.empty()) {
    return;
  }

  auto event_context = createEventContext();
  event_context->event_list = std::move(event_list);
  event_list.clear();

  buildEventPathMap(event_context);
  fire(event_context);
}

NTFSEventPublisherConfiguration NTFSEventPublisher::readConfiguration() {
  auto config_parser = Config::getParser("file_paths");
  const auto& json = config_parser->getData().doc();
  const auto& file_accesses = json["file_accesses"];

  NTFSEventPublisherConfiguration configuration = {};

  // We are not going to expand the paths, as we just need to get the
  // drive letter in order to restart the reader services
  Config::get().files([&configuration](
      const std::string& category, const std::vector<std::string>& path_list) {

    for (const auto& path : path_list) {
      const auto& drive_letter = path.front();
      configuration.insert(drive_letter);
    }
  });

  return configuration;
}

void NTFSEventPublisher::buildEventPathMap(NTFSEventContextRef event_context) {
  const auto& event_list = event_context->event_list;
  auto& ref_to_path_map = event_context->ref_to_path_map;

  // We aim at reducing disk access to minimize race conditions when
  // determining paths involved in the events we received
  for (const auto& journal_record : event_list) {
    std::string node_path;
    if (!getPathFromResolutionCache(node_path,
                                    journal_record.node_ref_number)) {
      if (!resolvePathFromComponentsCache(node_path, journal_record)) {
        auto status =
            resolvePathFromFileReferenceNumber(node_path,
                                               journal_record.drive_letter,
                                               journal_record.node_ref_number);

        if (!status.ok()) {
          VLOG(1) << status.getMessage();
          node_path = journal_record.name;
        }
      }
    }

    std::string parent_node_path;
    if (!getPathFromResolutionCache(parent_node_path,
                                    journal_record.parent_ref_number)) {
      // We can only attempt to use the path components cache if we have
      // information about the parent node
      auto it = d->path_components_cache.find(journal_record.parent_ref_number);
      bool perform_volume_query = true;

      if (it != d->path_components_cache.end()) {
        const auto& node_reference_info = it->second;

        USNJournalEventRecord parent_record = {};
        parent_record.name = node_reference_info.name;
        parent_record.node_ref_number = journal_record.parent_ref_number;
        parent_record.parent_ref_number = node_reference_info.parent;

        if (resolvePathFromComponentsCache(node_path, parent_record)) {
          perform_volume_query = false;
        }
      }

      if (perform_volume_query) {
        auto status = resolvePathFromFileReferenceNumber(
            parent_node_path,
            journal_record.drive_letter,
            journal_record.parent_ref_number);

        if (!status.ok()) {
          VLOG(1) << status.getMessage();
        }
      }
    }

    if (!node_path.empty()) {
      ref_to_path_map.insert({journal_record.node_ref_number, node_path});
    }

    if (!parent_node_path.empty()) {
      ref_to_path_map.insert(
          {journal_record.parent_ref_number, parent_node_path});
    }
  }
}

bool NTFSEventPublisher::getPathFromResolutionCache(
    std::string& path, const USNFileReferenceNumber& ref) {
  auto it = d->path_resolution_cache.find(ref);
  if (it != d->path_resolution_cache.end()) {
    path = it->second;
    return true;
  }

  return false;
}

bool NTFSEventPublisher::resolvePathFromComponentsCache(
    std::string& path, const USNJournalEventRecord& record) {
  path.clear();

  std::vector<std::string> components = {record.name};
  std::string base_path;

  auto current_ref = record.parent_ref_number;

  while (true) {
    // Attempt to get the full parent folder path from the cache
    if (getPathFromResolutionCache(base_path, current_ref)) {
      break;
    }

    // Attempt to get the next compoennt
    auto it = d->path_components_cache.find(current_ref);
    if (it == d->path_components_cache.end()) {
      return false;
    }

    const auto& current_component = it->second;
    components.push_back(current_component.name);

    current_ref = current_component.parent;
  }

  if (!base_path.empty()) {
    path = base_path;
  }

  for (auto it = components.rbegin(); it != components.rend(); it++) {
    path += "\\" + (*it);
  }

  updatePathResolutionCache(record.node_ref_number, path);
  return true;
}

Status NTFSEventPublisher::resolvePathFromFileReferenceNumber(
    std::string& path, char drive_letter, const USNFileReferenceNumber& ref) {
  path.clear();

  // Attempt to query the volume
  HANDLE drive_handle;
  auto status = getDriveHandle(drive_handle, drive_letter);
  if (!status.ok()) {
    return status;
  }

  FILE_ID_DESCRIPTOR native_node_id;
  GetNativeFileIdFromUSNReference(native_node_id, ref);

  auto node_handle =
      OpenFileById(drive_handle,
                   &native_node_id,
                   FILE_GENERIC_READ, // TODO(alessandro): Can we use 0?
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   nullptr,
                   FILE_FLAG_BACKUP_SEMANTICS);

  if (node_handle == INVALID_HANDLE_VALUE) {
    std::stringstream message;
    message << "Failed to open the file: ";

    std::string description;
    if (!getWindowsErrorDescription(description, GetLastError())) {
      description = "Unknown error";
    }

    message << description << " ";
    return Status(1, message.str());
  }

  // Get the path length first; the returned size includes the null terminator
  auto path_length = static_cast<size_t>(GetFinalPathNameByHandle(
      node_handle, nullptr, 0U, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS));
  if (GetLastError() != ERROR_NOT_ENOUGH_MEMORY) {
    ::CloseHandle(node_handle);
    return Status(1, "Failed to determine the path size");
  }

  path.resize(path_length - 1U);
  if (path.size() != path_length - 1U) {
    throw std::bad_alloc();
  }

  path_length =
      GetFinalPathNameByHandle(node_handle,
                               &path[0],
                               static_cast<DWORD>(path.size()),
                               FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  ::CloseHandle(node_handle);

  if (path_length != path.size() || GetLastError() != 0U) {
    return Status(1, "Failed query the file handle");
  }

  updatePathResolutionCache(ref, path);
  return Status(0);
}

Status NTFSEventPublisher::getDriveHandle(HANDLE& handle, char drive_letter) {
  UpgradeLock lock(d->drive_handle_map_mutex);

  auto it = d->drive_handle_map.find(drive_letter);
  if (it == d->drive_handle_map.end()) {
    handle = it->second;
    return Status(0);
  }

  WriteUpgradeLock wlock(lock);

  auto volume_path = std::string("\\\\.\\") + drive_letter + ":";
  handle = ::CreateFile(volume_path.c_str(),
                        FILE_GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS,
                        nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    std::stringstream message;
    message << "Failed to open the following drive: " << volume_path
            << " due to the following error: ";

    std::string description;
    if (!getWindowsErrorDescription(description, GetLastError())) {
      description = "Unknown error";
    }

    message << description;
    return Status(1, message.str());
  }

  d->drive_handle_map.insert({drive_letter, handle});
  return Status(0);
}

void NTFSEventPublisher::releaseDriveHandleMap() {
  WriteLock lock(d->drive_handle_map_mutex);

  for (const auto& p : d->drive_handle_map) {
    const auto handle = p.second;
    ::CloseHandle(handle);
  }

  d->drive_handle_map.clear();
}

void NTFSEventPublisher::updatePathResolutionCache(
    const USNFileReferenceNumber& ref, const std::string& path) {
  d->path_resolution_cache.insert({ref, path});

  if (d->path_resolution_cache.size() >= 20000U) {
    auto range_start = d->path_resolution_cache.begin();
    auto range_end = std::next(range_start, 10000U);

    d->path_resolution_cache.erase(range_start, range_end);
  }
}

NTFSEventPublisher::NTFSEventPublisher() : d(new PrivateData) {}

NTFSEventPublisher::~NTFSEventPublisher() {
  tearDown();
}

Status NTFSEventPublisher::setUp() {
  if (!FLAGS_enable_ntfs_event_publisher) {
    return Status(1, "Publisher disabled via configuration");
  }

  return Status(0, "OK");
}

void NTFSEventPublisher::configure() {
  if (!FLAGS_enable_ntfs_event_publisher) {
    return;
  }

  auto configuration = readConfiguration();
  restartJournalReaderServices(configuration);

  releaseDriveHandleMap();
}

Status NTFSEventPublisher::run() {
  if (!FLAGS_enable_ntfs_event_publisher) {
    return Status(1, "Publisher disabled via configuration");
  }

  auto event_list = acquireEvents();
  updatePathComponentCache(event_list);

  takeEventsAndNotifySuscribers(event_list);
  return Status(0, "OK");
}

void NTFSEventPublisher::tearDown() {
  if (!FLAGS_enable_ntfs_event_publisher) {
    return;
  }

  releaseDriveHandleMap();
}
} // namespace osquery
