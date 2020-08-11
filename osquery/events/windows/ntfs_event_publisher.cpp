/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <map>
#include <unordered_map>
#include <unordered_set>

#include <boost/chrono.hpp>
#include <boost/functional/hash.hpp>

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/errno.h>

#include "osquery/events/windows/ntfs_event_publisher.h"

namespace osquery {

FLAG(bool,
     enable_ntfs_event_publisher,
     false,
     "Enables the NTFS event publisher");

/// This debug flag will print the incoming events
HIDDEN_FLAG(bool,
            ntfs_event_publisher_debug,
            false,
            "Debug the NTFS event publisher");

REGISTER(NTFSEventPublisher, "event_publisher", "ntfs_event_publisher");

namespace {
namespace boostfs = boost::filesystem;

std::ostream& operator<<(std::ostream& stream, const NTFSEventRecord& event) {
  std::ios_base::fmtflags original_stream_settings(stream.flags());

  stream << "usn:\"" << event.update_sequence_number << "\" ";
  stream << "type:\"" << event.type << "\" ";
  stream << "record_timestamp:\"" << event.record_timestamp << "\" ";
  stream << "attributes:\"" << event.attributes << "\" ";
  stream << "drive_letter:\"" << event.drive_letter << "\" ";
  stream << "partial:\"" << (event.partial ? "true" : "false") << "\" ";

  if (!event.old_path.empty()) {
    stream << "old_path:\"" << event.old_path << "\" ";
  }

  stream << "path:\"" << event.path << "\"";

  stream.flags(original_stream_settings);
  return stream;
};
} // namespace

/// Private class data
struct NTFSEventPublisher::PrivateData final {
  /// Each reader service instance is mapped to the drive letter it is
  /// reading from
  std::unordered_map<char, USNJournalReaderInstance> reader_service_map;

  /// This mutex protects the reader service map
  Mutex reader_service_map_mutex;

  /// This map caches volume handles and root folder reference numbers
  std::unordered_map<char, VolumeData> volume_data_map;

  /// This mutex protects the volume data map
  Mutex volume_data_map_mutex;
};

void NTFSEventPublisher::restartJournalReaderServices(
    NTFSEventPublisherConfiguration& active_drives) {
  WriteLock lock(d_->reader_service_map_mutex);

  // Spawn new services
  for (const auto& drive_letter : active_drives) {
    if (d_->reader_service_map.find(drive_letter) !=
        d_->reader_service_map.end()) {
      continue;
    }

    auto context = std::make_shared<USNJournalReaderContext>();
    context->drive_letter = drive_letter;

    VLOG(1) << "Creating a new USNJournalReader service for drive "
            << drive_letter << ":";

    auto service = std::make_shared<USNJournalReader>(context);

    USNJournalReaderInstance instance = {};
    instance.reader = service;
    instance.context = context;
    d_->reader_service_map.insert({drive_letter, instance});

    Dispatcher::addService(service);
  }

  // Terminate the ones we no longer need
  for (auto service_it = d_->reader_service_map.begin();
       service_it != d_->reader_service_map.end();) {
    const auto& drive_letter = service_it->first;
    if (active_drives.count(drive_letter)) {
      service_it++;
      continue;
    }

    auto& service_instance = service_it->second;
    auto& service_context = service_instance.context;

    VLOG(1) << "Terminating the USNJournalReader service assigned to drive "
            << drive_letter << ":";

    service_context->terminate = true;
    service_it = d_->reader_service_map.erase(service_it);
  }
}

std::vector<USNJournalEventRecord> NTFSEventPublisher::acquireJournalRecords() {
  // We have a reader service for each volume; attempt to fetch data
  // from each one of them
  std::vector<USNJournalEventRecord> record_list;

  for (auto& reader_info : d_->reader_service_map) {
    auto& reader_instance = reader_info.second;
    auto& reader_context = reader_instance.context;

    std::vector<USNJournalEventRecord> new_record_list = {};

    {
      WriteLock lock(reader_context->processed_records_mutex);

      auto wait_status = reader_context->processed_records_cv.wait_for(
          lock, boost::chrono::seconds(1));

      if (wait_status == boost::cv_status::no_timeout) {
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

NTFSEventPublisherConfiguration NTFSEventPublisher::readConfiguration() {
  NTFSEventPublisherConfiguration configuration = {};

  // We are not going to expand the paths, as we just need to get the
  // drive letter in order to restart the reader services
  Config::get().files(
      [&configuration](const std::string& category,
                       const std::vector<std::string>& path_list) {
        for (const auto& path : path_list) {
          const auto& drive_letter = static_cast<char>(::toupper(path.front()));
          configuration.insert(drive_letter);
        }
      });

  return configuration;
}

Status NTFSEventPublisher::getPathFromReferenceNumber(
    std::string& path, char drive_letter, const USNFileReferenceNumber& ref) {
  path.clear();

  // Get the root folder handle
  VolumeData volume_data = {};
  auto status = getVolumeData(volume_data, drive_letter);
  if (!status.ok()) {
    return status;
  }

  // See if we have been requested to solve the root folder
  if (ref == volume_data.root_ref) {
    path.push_back(drive_letter);
    path.append(":\\");

    return Status::success();
  }

  // Convert the reference number to the native Windows structure
  FILE_ID_DESCRIPTOR native_file_id = {};
  GetNativeFileIdFromUSNReference(native_file_id, ref);

  // Attempt to open the file or folder
  auto handle =
      OpenFileById(volume_data.volume_handle,
                   &native_file_id,
                   0,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   nullptr,
                   FILE_FLAG_BACKUP_SEMANTICS);
  if (handle == INVALID_HANDLE_VALUE) {
    std::stringstream message;
    message << "Failed to open the file in volume " << drive_letter
            << ":\\. Error: ";

    std::wstring description;
    if (!getWindowsErrorDescription(description, ::GetLastError())) {
      description = L"Unknown error";
    }

    message << wstringToString(description);
    return Status::failure(message.str());
  }

  auto required_characters = static_cast<size_t>(::GetFinalPathNameByHandleW(
      handle, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS));

  if (required_characters == 0U) {
    auto error_code = ::GetLastError();
    ::CloseHandle(handle);

    std::stringstream message;
    message << "Failed to determine the path size for the file in volume "
            << drive_letter << ":\\. Error: ";

    std::wstring description;
    if (!getWindowsErrorDescription(description, error_code)) {
      description = L"Unknown error";
    }

    message << wstringToString(description.c_str());
    return Status::failure(message.str());
  }

  // We are going to add an additional byte, as we may or may not have the null
  // terminator already included depending on the operating system version
  std::wstring buffer;
  required_characters += 1U;

  buffer.resize(required_characters);
  if (buffer.size() != required_characters) {
    ::CloseHandle(handle);
    throw std::bad_alloc();
  }

  auto bytes_returned = static_cast<size_t>(
      ::GetFinalPathNameByHandleW(handle,
                                  &buffer[0],
                                  static_cast<DWORD>(buffer.size()),
                                  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS));

  auto error_code = ::GetLastError();
  ::CloseHandle(handle);

  if (bytes_returned == 0U || bytes_returned >= buffer.size()) {
    std::stringstream message;
    message << "Failed to acquire the path for the file in volume "
            << drive_letter << ":\\. Error: ";

    std::wstring description;
    if (!getWindowsErrorDescription(description, error_code)) {
      description = L"Unknown error";
    }

    message << wstringToString(description.c_str());
    return Status::failure(message.str());
  }

  // Paths follow this form: \\?\C:\\path\\to\\folder; skip the prefix
  path = wstringToString(buffer.c_str() + 4);
  buffer.clear();

  return Status::success();
}

Status NTFSEventPublisher::getPathFromParentFRN(
    std::string& path,
    ParentFRNCache& parent_frn_cache,
    char drive_letter,
    const std::string& basename,
    const USNFileReferenceNumber& ref) {
  auto& it = parent_frn_cache.find(ref);

  if (it == parent_frn_cache.end()) {
    Status status = getPathFromReferenceNumber(path, drive_letter, ref);

    if (!status.ok()) {
      return status;
    }

    parent_frn_cache[ref] = path;
  } else {
    path = it->second;
  }

  path.append("\\" + basename);

  return Status::success();
}

Status NTFSEventPublisher::getVolumeData(VolumeData& volume,
                                         char drive_letter) {
  UpgradeLock lock(d_->volume_data_map_mutex);

  {
    auto it = d_->volume_data_map.find(drive_letter);
    if (it != d_->volume_data_map.end()) {
      volume = it->second;
      return Status::success();
    }
  }

  WriteUpgradeLock wlock(lock);

  // Get a handle to the volume
  auto volume_path = std::string("\\\\.\\") + drive_letter + ":";

  VolumeData volume_data = {};
  volume_data.volume_handle =
      ::CreateFileW(stringToWstring(volume_path).c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    nullptr);

  if (volume_data.volume_handle == INVALID_HANDLE_VALUE) {
    std::stringstream message;
    message << "Failed to open the following drive: " << volume_path
            << " due to the following error: ";

    std::wstring description;
    if (!getWindowsErrorDescription(description, ::GetLastError())) {
      description = L"Unknown error";
    }

    message << wstringToString(description.c_str());
    return Status::failure(message.str());
  }

  // Get the root folder reference number
  std::string root_folder_path;
  root_folder_path.push_back(drive_letter);
  root_folder_path.append(":\\");

  volume_data.root_folder_handle =
      ::CreateFileW(stringToWstring(root_folder_path).c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    nullptr);

  if (volume_data.root_folder_handle == INVALID_HANDLE_VALUE) {
    auto error_code = ::GetLastError();
    ::CloseHandle(volume_data.volume_handle);

    std::stringstream message;
    message << "Failed to get the root folder handle for volume '"
            << drive_letter << "'. Error: ";

    std::wstring description;
    if (!getWindowsErrorDescription(description, error_code)) {
      description = L"Unknown error";
    }

    message << wstringToString(description.c_str());
    return Status::failure(message.str());
  }

  std::uint8_t buffer[2048] = {};
  DWORD bytes_read = 0U;

  auto status = ::DeviceIoControl(volume_data.root_folder_handle,
                                  FSCTL_READ_FILE_USN_DATA,
                                  nullptr,
                                  0,
                                  buffer,
                                  sizeof(buffer),
                                  &bytes_read,
                                  nullptr);
  if (!status) {
    auto error_code = ::GetLastError();

    ::CloseHandle(volume_data.volume_handle);
    ::CloseHandle(volume_data.root_folder_handle);

    std::stringstream message;
    message << "Failed to get the root reference number for volume '"
            << drive_letter << "'. Error: ";

    std::wstring description;
    if (!getWindowsErrorDescription(description, error_code)) {
      description = L"Unknown error";
    }

    message << wstringToString(description.c_str());
    return Status::failure(message.str());
  }

  auto usn_record = reinterpret_cast<USN_RECORD*>(buffer);
  if (!USNParsers::GetFileReferenceNumber(volume_data.root_ref, usn_record)) {
    ::CloseHandle(volume_data.volume_handle);
    ::CloseHandle(volume_data.root_folder_handle);

    return Status::failure("Failed to parse the root USN record");
  }

  d_->volume_data_map.insert({drive_letter, volume_data});
  return Status::success();
}

void NTFSEventPublisher::releaseDriveHandleMap() {
  WriteLock lock(d_->volume_data_map_mutex);

  for (const auto& p : d_->volume_data_map) {
    const auto& volume_data = p.second;
    ::CloseHandle(volume_data.volume_handle);
    ::CloseHandle(volume_data.root_folder_handle);
  }

  d_->volume_data_map.clear();
}

NTFSEventPublisher::NTFSEventPublisher() : d_(new PrivateData) {}

NTFSEventPublisher::~NTFSEventPublisher() {
  tearDown();
}

Status NTFSEventPublisher::setUp() {
  if (!FLAGS_enable_ntfs_event_publisher) {
    return Status::failure("NTFS event publisher disabled via configuration");
  }

  return Status::success();
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
    return Status::failure("NTFS event publisher disabled via configuration");
  }

  ReadLock lock(d_->reader_service_map_mutex);

  auto journal_records = acquireJournalRecords();
  if (journal_records.empty()) {
    return Status::success();
  }

  auto event_context = createEventContext();

  // We need to perform every step in the right order
  for (const auto& journal_record : journal_records) {
    // Locate the required service
    auto service_it = d_->reader_service_map.find(journal_record.drive_letter);
    assert(service_it != d_->reader_service_map.end());

    auto& service_instance = service_it->second;

    auto& parent_frn_cache = service_instance.parent_frn_cache;
    auto& rename_path_mapper = service_instance.rename_path_mapper;

    // Track rename records so that we can merge them into a single event
    bool skip_record = false;
    USNJournalEventRecord old_name_record = {};

    switch (journal_record.type) {
    case USNJournalEventRecord::Type::DirectoryRename_OldName:
    case USNJournalEventRecord::Type::FileRename_OldName: {
      rename_path_mapper.insert(
          {journal_record.node_ref_number, journal_record});

      skip_record = true;
      break;
    }

    case USNJournalEventRecord::Type::DirectoryRename_NewName: {
      // If we're renaming a directory, update the parent FRN cache.
      std::string dir;
      auto status = getPathFromReferenceNumber(
          dir, journal_record.drive_letter, journal_record.node_ref_number);

      if (!status.ok()) {
        TLOG << "Failed to get directory for parent FRN cache update";
      } else {
        parent_frn_cache[journal_record.node_ref_number] = dir;
      }
      // Intentional fallthrough.
    }
    case USNJournalEventRecord::Type::FileRename_NewName: {
      auto it = rename_path_mapper.find(journal_record.node_ref_number);
      if (it == rename_path_mapper.end()) {
        skip_record = true;
        VLOG(1) << "Failed to remap the rename records";
        break;
      }

      old_name_record = it->second;
      rename_path_mapper.erase(it);
    }
    }

    if (skip_record) {
      continue;
    }

    // Generate the new event
    NTFSEventRecord event(journal_record);

    // TODO(woodruffw): This is failing occasionally for files that do exist
    // on disk, but only on the first call to look them up. I'm not
    // sure why yet, but falling back on the parent FRN cache and
    // building the path from it works for now.
    // See https://github.com/osquery/osquery/issues/5848
    auto status = getPathFromReferenceNumber(event.path,
                                             journal_record.drive_letter,
                                             journal_record.node_ref_number);
    if (!status.ok()) {
      TLOG << "FRN pathname lookup failed, trying parent: "
           << status.getMessage();

      status = getPathFromParentFRN(event.path,
                                    parent_frn_cache,
                                    journal_record.drive_letter,
                                    journal_record.name,
                                    journal_record.parent_ref_number);

      if (!status.ok()) {
        VLOG(1) << "Parent FRN lookup failed: " << status.getMessage();

        event.path = journal_record.name;
        event.partial = true;
      }
    }

    if (old_name_record.drive_letter != 0U) {
      status = getPathFromParentFRN(event.old_path,
                                    parent_frn_cache,
                                    old_name_record.drive_letter,
                                    old_name_record.name,
                                    old_name_record.parent_ref_number);
      if (!status.ok()) {
        VLOG(1) << "Parent FRN lookup failed: " << status.getMessage();
        event.partial = true;
      }
    }

    if (FLAGS_ntfs_event_publisher_debug) {
      TLOG << "NTFSEventPublisher event: " << event;
    }

    event_context->event_list.push_back(std::move(event));
  }

  // Put a limit on the size of the caches we are using
  // NOTE(woodruffw): We could also try to incrementally free up
  // the parent FRN cache by tracking DirectoryDeletions.
  for (auto& p : d_->reader_service_map) {
    auto& service_instance = p.second;

    auto& parent_frn_cache = service_instance.parent_frn_cache;
    auto& rename_path_mapper = service_instance.rename_path_mapper;

    if (rename_path_mapper.size() >= 2000U) {
      auto range_start = rename_path_mapper.begin();
      auto range_end = std::next(range_start, 1000U);

      rename_path_mapper.erase(range_start, range_end);
    }

    if (parent_frn_cache.size() >= 2000U) {
      auto range_start = parent_frn_cache.begin();
      auto range_end = std::next(range_start, 1000U);

      parent_frn_cache.erase(range_start, range_end);
    }
  }

  fire(event_context);

  return Status::success();
}

void NTFSEventPublisher::tearDown() {
  if (!FLAGS_enable_ntfs_event_publisher) {
    return;
  }

  releaseDriveHandleMap();
}
} // namespace osquery
