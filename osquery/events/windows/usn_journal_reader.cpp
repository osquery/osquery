/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <array>
#include <ctime>
#include <iomanip>
#include <map>
#include <sstream>

#include <Windows.h>
#include <winioctl.h>

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/system/errno.h>

#include "osquery/core/windows/wmi.h"
#include "osquery/events/windows/usn_journal_reader.h"

#ifndef FILE_ATTRIBUTE_RECALL_ON_OPEN
#define FILE_ATTRIBUTE_RECALL_ON_OPEN 0x00040000
#endif

#ifndef FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS 0x00400000
#endif

namespace osquery {
/// This debug flag will print the incoming events
HIDDEN_FLAG(bool,
            usn_journal_reader_debug,
            false,
            "Debug USN journal messages");

// clang-format off
const std::unordered_map<int, std::string> kWindowsFileAttributeMap = {
    {FILE_ATTRIBUTE_ARCHIVE, "FILE_ATTRIBUTE_ARCHIVE"},
    {FILE_ATTRIBUTE_COMPRESSED, "FILE_ATTRIBUTE_COMPRESSED"},
    {FILE_ATTRIBUTE_DEVICE, "FILE_ATTRIBUTE_DEVICE"},
    {FILE_ATTRIBUTE_DIRECTORY, "FILE_ATTRIBUTE_DIRECTORY"},
    {FILE_ATTRIBUTE_ENCRYPTED, "FILE_ATTRIBUTE_ENCRYPTED"},
    {FILE_ATTRIBUTE_HIDDEN, "FILE_ATTRIBUTE_HIDDEN"},
    {FILE_ATTRIBUTE_INTEGRITY_STREAM, "FILE_ATTRIBUTE_INTEGRITY_STREAM"},
    {FILE_ATTRIBUTE_NORMAL, "FILE_ATTRIBUTE_NORMAL"},
    {FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED"},
    {FILE_ATTRIBUTE_NO_SCRUB_DATA, "FILE_ATTRIBUTE_NO_SCRUB_DATA"},
    {FILE_ATTRIBUTE_OFFLINE, "FILE_ATTRIBUTE_OFFLINE"},
    {FILE_ATTRIBUTE_READONLY, "FILE_ATTRIBUTE_READONLY"},
    {FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS"},
    {FILE_ATTRIBUTE_RECALL_ON_OPEN, "FILE_ATTRIBUTE_RECALL_ON_OPEN"},
    {FILE_ATTRIBUTE_REPARSE_POINT, "FILE_ATTRIBUTE_REPARSE_POINT"},
    {FILE_ATTRIBUTE_SPARSE_FILE, "FILE_ATTRIBUTE_SPARSE_FILE"},
    {FILE_ATTRIBUTE_SYSTEM, "FILE_ATTRIBUTE_SYSTEM"},
    {FILE_ATTRIBUTE_TEMPORARY, "FILE_ATTRIBUTE_TEMPORARY"},
    {FILE_ATTRIBUTE_VIRTUAL, "FILE_ATTRIBUTE_VIRTUAL"}};
// clang-format on

// clang-format off
const std::unordered_map<USNJournalEventRecord::Type, std::string>
    kNTFSEventToStringMap = {
        {USNJournalEventRecord::Type::AttributesChange, "AttributesChange"},
        {USNJournalEventRecord::Type::ExtendedAttributesChange, "ExtendedAttributesChange"},
        {USNJournalEventRecord::Type::DirectoryCreation, "DirectoryCreation"},
        {USNJournalEventRecord::Type::FileWrite, "FileWrite"},
        {USNJournalEventRecord::Type::DirectoryOverwrite, "DirectoryOverwrite"},
        {USNJournalEventRecord::Type::FileOverwrite, "FileOverwrite"},
        {USNJournalEventRecord::Type::DirectoryTruncation, "DirectoryTruncation"},
        {USNJournalEventRecord::Type::FileTruncation, "FileTruncation"},
        {USNJournalEventRecord::Type::TransactedDirectoryChange, "TransactedDirectoryChange"},
        {USNJournalEventRecord::Type::TransactedFileChange, "TransactedFileChange"},
        {USNJournalEventRecord::Type::FileCreation, "FileCreation"},
        {USNJournalEventRecord::Type::DirectoryDeletion, "DirectoryDeletion"},
        {USNJournalEventRecord::Type::FileDeletion, "FileDeletion"},
        {USNJournalEventRecord::Type::DirectoryLinkChange, "DirectoryLinkChange"},
        {USNJournalEventRecord::Type::FileLinkChange, "FileLinkChange"},
        {USNJournalEventRecord::Type::DirectoryIndexingSettingChange, "DirectoryIndexingSettingChange"},
        {USNJournalEventRecord::Type::FileIndexingSettingChange, "FileIndexingSettingChange"},
        {USNJournalEventRecord::Type::DirectoryIntegritySettingChange, "DirectoryIntegritySettingChange"},
        {USNJournalEventRecord::Type::FileIntegritySettingChange, "FileIntegritySettingChange"},
        {USNJournalEventRecord::Type::AlternateDataStreamWrite, "AlternateDataStreamWrite"},
        {USNJournalEventRecord::Type::AlternateDataStreamOverwrite, "AlternateDataStreamOverwrite"},
        {USNJournalEventRecord::Type::AlternateDataStreamTruncation, "AlternateDataStreamTruncation"},
        {USNJournalEventRecord::Type::AlternateDataStreamChange, "AlternateDataStreamChange"},
        {USNJournalEventRecord::Type::DirectoryObjectIdChange, "DirectoryObjectIdChange"},
        {USNJournalEventRecord::Type::FileObjectIdChange, "FileObjectIdChange"},
        {USNJournalEventRecord::Type::DirectoryRename_NewName, "DirectoryRename_NewName"},
        {USNJournalEventRecord::Type::FileRename_NewName, "FileRename_NewName"},
        {USNJournalEventRecord::Type::DirectoryRename_OldName, "DirectoryRename_OldName"},
        {USNJournalEventRecord::Type::FileRename_OldName, "FileRename_OldName"},
        {USNJournalEventRecord::Type::ReparsePointChange, "ReparsePointChange"},
        {USNJournalEventRecord::Type::DirectorySecurityAttributesChange, "DirectorySecurityAttributesChange"},
        {USNJournalEventRecord::Type::FileSecurityAttributesChange, "FileSecurityAttributesChange"}};
// clang-format on

namespace {
/// Read buffer size
const size_t kUSNJournalReaderBufferSize = 4096U;

/// This variable holds the list of change events we are interested in. Order
/// is important, as it determines the priority when decompressing/splitting
/// the `reason` field of the USN journal records.
const std::vector<DWORD> kUSNChangeReasonFlagList = {
    USN_REASON_FILE_CREATE,
    USN_REASON_DATA_OVERWRITE,
    USN_REASON_DATA_TRUNCATION,
    USN_REASON_DATA_EXTEND,
    USN_REASON_FILE_DELETE,

    USN_REASON_RENAME_OLD_NAME,
    USN_REASON_RENAME_NEW_NAME,

    USN_REASON_NAMED_DATA_EXTEND,
    USN_REASON_NAMED_DATA_OVERWRITE,
    USN_REASON_NAMED_DATA_TRUNCATION,

    USN_REASON_TRANSACTED_CHANGE,
    USN_REASON_BASIC_INFO_CHANGE,
    USN_REASON_EA_CHANGE,
    USN_REASON_HARD_LINK_CHANGE,
    USN_REASON_INDEXABLE_CHANGE,
    USN_REASON_INTEGRITY_CHANGE,
    USN_REASON_STREAM_CHANGE,
    USN_REASON_OBJECT_ID_CHANGE,
    USN_REASON_REPARSE_POINT_CHANGE,
    USN_REASON_SECURITY_CHANGE};

// This map is used to convert the `reason` field of the USN record to
// our internal type. In the pair type, the first field is selected if
// the attributes indicate that the event is operating on a directory
// clang-format off
const std::unordered_map<int, std::pair<USNJournalEventRecord::Type, USNJournalEventRecord::Type>> kReasonConversionMap = {
  // USN `reason` bit                 Internal event for directories                                    Internal event for non-directories
  {USN_REASON_BASIC_INFO_CHANGE,      {USNJournalEventRecord::Type::AttributesChange,                   USNJournalEventRecord::Type::AttributesChange}},
  {USN_REASON_EA_CHANGE,              {USNJournalEventRecord::Type::AttributesChange,                   USNJournalEventRecord::Type::ExtendedAttributesChange}},
  {USN_REASON_DATA_EXTEND,            {USNJournalEventRecord::Type::DirectoryCreation,                  USNJournalEventRecord::Type::FileWrite}},
  {USN_REASON_DATA_OVERWRITE,         {USNJournalEventRecord::Type::DirectoryOverwrite,                 USNJournalEventRecord::Type::FileOverwrite}},
  {USN_REASON_DATA_TRUNCATION,        {USNJournalEventRecord::Type::DirectoryTruncation,                USNJournalEventRecord::Type::FileTruncation}},
  {USN_REASON_TRANSACTED_CHANGE,      {USNJournalEventRecord::Type::TransactedDirectoryChange,          USNJournalEventRecord::Type::TransactedFileChange}},
  {USN_REASON_FILE_CREATE,            {USNJournalEventRecord::Type::DirectoryCreation,                  USNJournalEventRecord::Type::FileCreation}},
  {USN_REASON_FILE_DELETE,            {USNJournalEventRecord::Type::DirectoryDeletion,                  USNJournalEventRecord::Type::FileDeletion}},
  {USN_REASON_HARD_LINK_CHANGE,       {USNJournalEventRecord::Type::DirectoryLinkChange,                USNJournalEventRecord::Type::FileLinkChange}},
  {USN_REASON_INDEXABLE_CHANGE,       {USNJournalEventRecord::Type::DirectoryIndexingSettingChange,     USNJournalEventRecord::Type::FileIndexingSettingChange}},
  {USN_REASON_INTEGRITY_CHANGE,       {USNJournalEventRecord::Type::DirectoryIntegritySettingChange,    USNJournalEventRecord::Type::FileIntegritySettingChange}},
  {USN_REASON_NAMED_DATA_EXTEND,      {USNJournalEventRecord::Type::AlternateDataStreamWrite,           USNJournalEventRecord::Type::AlternateDataStreamWrite}},
  {USN_REASON_NAMED_DATA_OVERWRITE,   {USNJournalEventRecord::Type::AlternateDataStreamOverwrite,       USNJournalEventRecord::Type::AlternateDataStreamOverwrite}},
  {USN_REASON_NAMED_DATA_TRUNCATION,  {USNJournalEventRecord::Type::AlternateDataStreamTruncation,      USNJournalEventRecord::Type::AlternateDataStreamTruncation}},
  {USN_REASON_STREAM_CHANGE,          {USNJournalEventRecord::Type::AlternateDataStreamChange,          USNJournalEventRecord::Type::AlternateDataStreamChange}},
  {USN_REASON_OBJECT_ID_CHANGE,       {USNJournalEventRecord::Type::DirectoryObjectIdChange,            USNJournalEventRecord::Type::FileObjectIdChange}},
  {USN_REASON_RENAME_NEW_NAME,        {USNJournalEventRecord::Type::DirectoryRename_NewName,            USNJournalEventRecord::Type::FileRename_NewName}},
  {USN_REASON_RENAME_OLD_NAME,        {USNJournalEventRecord::Type::DirectoryRename_OldName,            USNJournalEventRecord::Type::FileRename_OldName}},
  {USN_REASON_REPARSE_POINT_CHANGE,   {USNJournalEventRecord::Type::ReparsePointChange,                 USNJournalEventRecord::Type::ReparsePointChange}},
  {USN_REASON_SECURITY_CHANGE,        {USNJournalEventRecord::Type::DirectorySecurityAttributesChange,  USNJournalEventRecord::Type::FileSecurityAttributesChange}}
};
// clang-format on

/// Aggregates the flag list into a bit mask; this is used to avoid having to
/// repeat the flag list twice in two different formats
DWORD GetUSNChangeReasonFlagMask() {
  DWORD result = 0U;
  for (const auto& bit : kUSNChangeReasonFlagList) {
    result |= bit;
  }

  return result;
}
} // namespace

bool USNFileReferenceNumber::operator==(
    const USNFileReferenceNumber& rhs) const {
  return data.size() == rhs.data.size() && data == rhs.data;
}
bool USNFileReferenceNumber::operator!=(
    const USNFileReferenceNumber& rhs) const {
  return !(*this == rhs);
}
bool USNFileReferenceNumber::operator<(
    const USNFileReferenceNumber& rhs) const {
  return data < rhs.data;
}

std::string USNFileReferenceNumber::str() const {
  std::ostringstream os;
  for (auto& i : data) {
    os << std::to_string(i);
  }

  return os.str();
};

struct USNJournalReader::PrivateData final {
  /// Shared data between this service and the publisher
  USNJournalReaderContextRef journal_reader_context;

  /// This is the handle for the volume mounted at
  /// journal_reader_context->drive_letter
  HANDLE volume_handle{INVALID_HANDLE_VALUE};

  /// Read buffer
  std::array<std::uint8_t, kUSNJournalReaderBufferSize> read_buffer;

  /// How many bytes the service was able to read during the last acquireRecords
  /// call
  size_t bytes_received{0U};

  /// Initial sequence number; this is the USN that we saw for the first time
  /// when launching the service
  USN initial_sequence_number;

  /// Sequence number used to query the volume journal
  USN next_update_seq_number{0U};

  /// The volume journal id
  DWORDLONG journal_id{0U};

  /// The volume path (i.e.: \\.\C:)
  std::string volume_path;

  /// This map is used to deduplicate the journal records; when the maximum size
  /// is reached, the oldest entries are automatically cleared
  USNPerFileLastRecordType per_file_last_record_type_map;
};

Status USNJournalReader::initialize() {
  // Create a handle to the volume and save it
  d_->volume_path =
      std::string("\\\\.\\") + d_->journal_reader_context->drive_letter + ":";

  d_->volume_handle =
      ::CreateFileW(stringToWstring(d_->volume_path).c_str(),
                    FILE_GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    0,
                    nullptr);

  if (d_->volume_handle == INVALID_HANDLE_VALUE) {
    std::stringstream error_message;
    error_message << "Failed to get a handle to the following volume: "
                  << d_->volume_path << ". Terminating...";

    return Status::failure(error_message.str());
  }

  // Acquire a valid USN that we will use to start querying the journal
  USN_JOURNAL_DATA_V2 journal_data = {};
  DWORD bytes_received = 0U;
  auto status = ::DeviceIoControl(d_->volume_handle,
                                  FSCTL_QUERY_USN_JOURNAL,
                                  nullptr,
                                  0,
                                  &journal_data,
                                  sizeof(journal_data),
                                  &bytes_received,
                                  nullptr);

  if (!status || bytes_received != sizeof(journal_data)) {
    auto error_code = ::GetLastError();

    ::CloseHandle(d_->volume_handle);
    d_->volume_handle = INVALID_HANDLE_VALUE;

    std::stringstream error_message;
    error_message << "Failed to acquire the initial journal ID and sequence "
                     "number for the following volume: "
                  << d_->volume_path << ". Error message: ";

    std::wstring description;
    if (!getWindowsErrorDescription(description, error_code)) {
      description = L"Unknown error";
    }
    error_message << wstringToString(description.c_str());

    return Status::failure(error_message.str());
  }

  /// This is the next USN identifier, to be used when requesting the next
  /// updates; we keep the initial ones for queries
  d_->initial_sequence_number = journal_data.NextUsn;
  d_->next_update_seq_number = d_->initial_sequence_number;

  // Also save the journal id
  d_->journal_id = journal_data.UsnJournalID;

  return Status::success();
}

Status USNJournalReader::acquireRecords() {
  static const DWORD flag_mask = GetUSNChangeReasonFlagMask();

  // Attempt to fill the read buffer; it is important to also support at least
  // V3 records, as V2 are disabled when range tracking is activated. We are
  // skipping them for now, but we can easily enable them by changing the last
  // field in this structure (the code will automatically skip them for now)
  READ_USN_JOURNAL_DATA_V1 read_data_command = {0U,
                                                flag_mask,
                                                0U,
                                                1U,
                                                kUSNJournalReaderBufferSize,
                                                d_->journal_id,
                                                2U,
                                                3U};

  read_data_command.StartUsn = d_->next_update_seq_number;

  DWORD bytes_received = 0U;
  auto status = ::DeviceIoControl(d_->volume_handle,
                                  FSCTL_READ_USN_JOURNAL,
                                  &read_data_command,
                                  sizeof(read_data_command),
                                  d_->read_buffer.data(),
                                  static_cast<DWORD>(d_->read_buffer.size()),
                                  &bytes_received,
                                  nullptr);

  if (!status || bytes_received < sizeof(USN)) {
    std::stringstream error_message;
    error_message << "Failed to read the journal of the following volume: "
                  << d_->volume_path << ". Error message: ";

    std::wstring description;
    if (!getWindowsErrorDescription(description, ::GetLastError())) {
      description = L"Unknown error";
    }
    error_message << wstringToString(description.c_str());

    return Status::failure(error_message.str());
  }

  d_->bytes_received = static_cast<size_t>(bytes_received);

  // Save the new update sequence number for the next query
  auto next_update_seq_number_ptr =
      reinterpret_cast<USN*>(d_->read_buffer.data());

  // NOTE(woodruffw): It's worth investigating whether we can use gaps
  // in the sequence number here to detect whether or not
  // we're missing events on a busy system. Does NTFS guarantee
  // strictly sequential USNs? What about other FSes that implement
  // the change journal?
  // See: https://github.com/osquery/osquery/pull/5371#discussion_r332122819
  d_->next_update_seq_number = *next_update_seq_number_ptr;
  return Status::success();
}

// V4 records are only used for range tracking; they are not useful for us since
// they are emitted only after a file has been closed.
//
// NTFS range tracking is enabled or disabled system-wide, and MSDN mention that
// system components may toggle it on. When it is activated, the filesystem will
// stop outputting V2 records, and only use V3 and V4 instead.
Status USNJournalReader::processAcquiredRecords(
    std::vector<USNJournalEventRecord>& record_list) {
  record_list.clear();

  const auto buffer_end_ptr = d_->read_buffer.data() + d_->bytes_received;

  auto current_buffer_ptr = d_->read_buffer.data() + sizeof(USN);

  // NOTE(woodruffw): According to MSDN, all DeviceIoControl ops that work with
  // USN_RECORD_V2 and USN_RECORD_V3 return buffers where the records
  // are 64 bits aligned from the buffer start. Experimentally that hasn't
  // been a problem yet, but we're not doing that check + correction below.
  while (current_buffer_ptr < buffer_end_ptr) {
    const auto current_record =
        reinterpret_cast<const USN_RECORD*>(current_buffer_ptr);

    const auto next_buffer_ptr =
        current_buffer_ptr + current_record->RecordLength;
    if (next_buffer_ptr > buffer_end_ptr || current_record->RecordLength <= 0) {
      return Status::failure("Received a malformed USN_RECORD. Terminating...");
    }

    auto status =
        ProcessAndAppendUSNRecord(record_list,
                                  current_record,
                                  d_->per_file_last_record_type_map,
                                  d_->journal_reader_context->drive_letter);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
    }

    current_buffer_ptr = next_buffer_ptr;
  }

  return Status::success();
}

void USNJournalReader::dispatchEventRecords(
    const std::vector<USNJournalEventRecord>& record_list) {
  if (record_list.empty()) {
    return;
  }

  // Notify the publisher that we have new records ready to be acquired
  auto& context = d_->journal_reader_context;

  {
    WriteLock lock(context->processed_records_mutex);

    context->processed_record_list.reserve(
        context->processed_record_list.size() + record_list.size());

    context->processed_record_list.insert(context->processed_record_list.end(),
                                          record_list.begin(),
                                          record_list.end());

    context->processed_records_cv.notify_all();
  }
}

void USNJournalReader::start() {
  // Acquire a handle to the device, as well as the journal id and the initial
  // sequence number
  auto status = initialize();
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    return;
  }

  // Enter the main loop, listening for journal changes
  while (!interrupted() && !d_->journal_reader_context->terminate) {
    status = acquireRecords();
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
      return;
    }

    // Process the records
    std::vector<USNJournalEventRecord> record_list;
    status = processAcquiredRecords(record_list);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
      return;
    }

    // Send the new records to the event publisher
    dispatchEventRecords(record_list);
  }
}

void USNJournalReader::stop() {
  if (d_->volume_handle != INVALID_HANDLE_VALUE) {
    ::CloseHandle(d_->volume_handle);
    d_->volume_handle = INVALID_HANDLE_VALUE;
  }
}

USNJournalReader::USNJournalReader(
    USNJournalReaderContextRef journal_reader_context)
    : InternalRunnable("USNJournalReader"), d_(new PrivateData) {
  d_->journal_reader_context = journal_reader_context;
}

USNJournalReader::~USNJournalReader() {}

/* When possible, the change journal will "compress" records for a single
 * FRN together by marking different bits on the `Reason` member high,
 * each bit representing a different journaled event. This function
 * iterates over those bits, extracting each event into a standalone
 * record and placing those decompressed records into a vector for
 * later consumption.
 *
 * TODO: Needs tests; see https://github.com/osquery/osquery/issues/5847
 */
Status USNJournalReader::DecompressRecord(
    std::vector<USNJournalEventRecord>& new_records,
    const USNJournalEventRecord& base_record,
    DWORD journal_record_reason,
    USNPerFileLastRecordType& per_file_last_record_type_map) {
  for (const auto& reason_bit : kUSNChangeReasonFlagList) {
    if ((journal_record_reason & reason_bit) == 0) {
      continue;
    }

    auto new_record = base_record;
    if (!USNParsers::GetEventType(
            new_record.type, reason_bit, base_record.attributes)) {
      return Status::failure("Failed to get the event type");
    }

    bool emit_record = true;
    auto last_file_state_it =
        per_file_last_record_type_map.find(new_record.node_ref_number);

    if (last_file_state_it == per_file_last_record_type_map.end()) {
      emit_record = true;

    } else {
      auto last_file_state = last_file_state_it->second;
      emit_record = last_file_state != new_record.type;
    }

    if (emit_record) {
      if (FLAGS_usn_journal_reader_debug) {
        TLOG << new_record;
      }

      new_records.push_back(std::move(new_record));
      per_file_last_record_type_map[new_record.node_ref_number] =
          new_record.type;

      // clear out space if map if hit size limit (oldest records, first)
      if (per_file_last_record_type_map.size() >= 20000U) {
        auto range_start = per_file_last_record_type_map.begin();
        auto range_end = std::next(range_start, 10000U);

        per_file_last_record_type_map.erase(range_start, range_end);
      }
    }
  }

  return Status::success();
}

// TODO: Needs tests; see https://github.com/osquery/osquery/issues/5847
Status USNJournalReader::ProcessAndAppendUSNRecord(
    std::vector<USNJournalEventRecord>& record_list,
    const USN_RECORD* record,
    USNPerFileLastRecordType& per_file_last_record_type_map,
    char drive_letter) {
  // We don't care about range tracking records
  if (record->MajorVersion == 4U) {
    return Status::success();
  }

  USNJournalEventRecord base_event_record = {};
  base_event_record.drive_letter = drive_letter;

  base_event_record.journal_record_version =
      static_cast<size_t>(record->MajorVersion);

  if (!USNParsers::GetUpdateSequenceNumber(
          base_event_record.update_sequence_number, record)) {
    return Status::failure(
        "Failed to get the update sequence number from the record");
  }

  if (!USNParsers::GetFileReferenceNumber(base_event_record.node_ref_number,
                                          record)) {
    return Status::failure("Failed to get the file reference number");
  }

  if (!USNParsers::GetParentFileReferenceNumber(
          base_event_record.parent_ref_number, record)) {
    return Status::failure("Failed to get the parent reference number");
  }

  if (!USNParsers::GetTimeStamp(base_event_record.record_timestamp, record)) {
    return Status::failure("Failed to get the timestamp");
  }

  if (!USNParsers::GetAttributes(base_event_record.attributes, record)) {
    return Status::failure("Failed to get the file attributes");
  }

  if (!USNParsers::GetEventString(base_event_record.name, record)) {
    return Status::failure("Failed to acquire the file name");
  }

  // Now decompress the record by splitting the `reason` field
  DWORD reason;
  if (!USNParsers::GetReason(reason, record)) {
    return Status::failure("Failed to get the `reason` field from the record");
  }

  auto status = DecompressRecord(
      record_list, base_event_record, reason, per_file_last_record_type_map);
  if (!status.ok()) {
    return status;
  }

  return Status::success();
}

void GetNativeFileIdFromUSNReference(FILE_ID_DESCRIPTOR& file_id,
                                     const USNFileReferenceNumber& ref) {
  file_id = {};
  file_id.dwSize = sizeof(FILE_ID_DESCRIPTOR);

  if (ref.data.size() <= sizeof(LARGE_INTEGER)) {
    file_id.Type = FileIdType;
    std::copy(ref.data.begin(),
              ref.data.end(),
              reinterpret_cast<std::uint8_t*>(&file_id.FileId.QuadPart));
  } else {
    /* NOTE(woodruffw): osquery retains Windows 7 compatibility,
       which means that we don't have access to the FILE_ID_128
       member of FILE_ID_DESCRIPTOR's id union. We use GUID instead,
       since it's the same width and the actual typing probably won't
       matter for our purposes.
     */
    file_id.Type = ObjectIdType;
    std::copy(ref.data.begin(),
              ref.data.end(),
              reinterpret_cast<std::uint8_t*>(&file_id.ObjectId));
  }
}

namespace USNParsers {
bool GetUpdateSequenceNumber(USN& usn, const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  switch (record->MajorVersion) {
  case 2U:
    usn = reinterpret_cast<const USN_RECORD_V2*>(record)->Usn;
    return true;

  case 3U:
    usn = reinterpret_cast<const USN_RECORD_V3*>(record)->Usn;
    return true;

  default:
    return false;
  }
}

bool GetFileReferenceNumber(USNFileReferenceNumber& ref_number,
                            const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  switch (record->MajorVersion) {
  case 2U: {
    ref_number =
        reinterpret_cast<const USN_RECORD_V2*>(record)->FileReferenceNumber;
    return true;
  }

  case 3U: {
    ref_number =
        reinterpret_cast<const USN_RECORD_V3*>(record)->FileReferenceNumber;
    return true;
  }

  default:
    return false;
  }
}

bool GetParentFileReferenceNumber(USNFileReferenceNumber& ref_number,
                                  const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  switch (record->MajorVersion) {
  case 2U: {
    ref_number = reinterpret_cast<const USN_RECORD_V2*>(record)
                     ->ParentFileReferenceNumber;
    return true;
  }

  case 3U: {
    ref_number = reinterpret_cast<const USN_RECORD_V3*>(record)
                     ->ParentFileReferenceNumber;
    return true;
  }

  default:
    return false;
  }
}

bool GetTimeStamp(std::time_t& record_timestamp, const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  LARGE_INTEGER update_timestamp = {};

  switch (record->MajorVersion) {
  case 2U:
    update_timestamp =
        reinterpret_cast<const USN_RECORD_V2*>(record)->TimeStamp;
    break;

  case 3U:
    update_timestamp =
        reinterpret_cast<const USN_RECORD_V3*>(record)->TimeStamp;
    break;

  default:
    return false;
  }

  record_timestamp = longIntToUnixtime(update_timestamp);
  return true;
}

bool GetAttributes(DWORD& attributes, const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  switch (record->MajorVersion) {
  case 2U:
    attributes = reinterpret_cast<const USN_RECORD_V2*>(record)->FileAttributes;
    return true;

  case 3U:
    attributes = reinterpret_cast<const USN_RECORD_V3*>(record)->FileAttributes;
    return true;

  default:
    return false;
  }
}

bool GetReason(DWORD& reason, const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  switch (record->MajorVersion) {
  case 2U:
    reason = reinterpret_cast<const USN_RECORD_V2*>(record)->Reason;
    return true;

  case 3U:
    reason = reinterpret_cast<const USN_RECORD_V3*>(record)->Reason;
    return true;

  default:
    return false;
  }
}

bool GetEventType(USNJournalEventRecord::Type& type,
                  DWORD reason_bit,
                  DWORD journal_file_attributes) {
  auto it = kReasonConversionMap.find(reason_bit);
  if (it == kReasonConversionMap.end()) {
    return false;
  }

  bool is_directory = (journal_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

  const auto& event_type_pair = it->second;
  if (is_directory) {
    type = event_type_pair.first;
  } else {
    type = event_type_pair.second;
  }

  return true;
}

bool GetEventString(std::string& buffer, const USN_RECORD* record) {
  assert(record->MajorVersion != 4U);

  const wchar_t* filename = nullptr;
  size_t name_length = 0U;
  size_t record_length = 0U;

  // NOTE(woodruffw): I think this could be simplified: both V2 and V3 records
  // contain a direct pointer to the filename that's guaranteed to be valid
  // under the FSCTL_* constants we're using, so we might not need to muck
  // with the offset at all.
  switch (record->MajorVersion) {
  case 2U: {
    auto record_v2 = reinterpret_cast<const USN_RECORD_V2*>(record);

    filename = record_v2->FileName;
    name_length = static_cast<size_t>(record_v2->FileNameLength);
    record_length = static_cast<size_t>(record_v2->RecordLength);

    break;
  }

  case 3U: {
    auto record_v3 = reinterpret_cast<const USN_RECORD_V3*>(record);

    filename = record_v3->FileName;
    name_length = static_cast<size_t>(record_v3->FileNameLength);
    record_length = static_cast<size_t>(record_v3->RecordLength);

    break;
  }

  default:
    return false;
  }

  if (name_length == 0U) {
    buffer.clear();
    return true;
  }

  // Make sure we are not going outside of the record boundaries
  auto record_start_ptr = reinterpret_cast<const uint8_t*>(record);
  auto record_end_ptr = record_start_ptr + record_length;

  auto string_end_ptr =
      reinterpret_cast<const uint8_t*>(filename) + name_length;

  if (string_end_ptr > record_end_ptr) {
    LOG(ERROR) << "Invalid string length"
               << "record size: " << record_length
               << " name length: " << name_length;

    return false;
  }

  std::wstring wide_chars_file_name(filename, (name_length / sizeof(wchar_t)));
  buffer = wstringToString(wide_chars_file_name.c_str());

  return true;
}
} // namespace USNParsers

std::ostream& operator<<(std::ostream& stream,
                         const USNJournalEventRecord::Type& type) {
  auto it = kNTFSEventToStringMap.find(type);
  if (it == kNTFSEventToStringMap.end()) {
    stream << "UnknownEventRecordType";
    return stream;
  }

  const auto& label = it->second;
  stream << label;

  return stream;
}

std::ostream& operator<<(std::ostream& stream,
                         const USNFileReferenceNumber& ref) {
  std::ios_base::fmtflags original_stream_settings(stream.flags());

  FILE_ID_DESCRIPTOR native_file_id = {};
  GetNativeFileIdFromUSNReference(native_file_id, ref);

  stream << "0x";

  switch (native_file_id.Type) {
  case FileIdType: {
    stream << std::hex << std::setfill('0') << std::setw(16)
           << native_file_id.FileId.QuadPart;
    break;
  }
  default: {
    const auto& object_id = native_file_id.ObjectId;
    stream << std::hex << std::setfill('0');
    stream << std::setw(8) << object_id.Data1;
    stream << std::setw(4) << object_id.Data2;
    stream << std::setw(4) << object_id.Data3;
    for (auto i = 0; i < 8; ++i) {
      stream << std::setw(2) << object_id.Data4[i];
    }
    break;
  }
  }

  stream.flags(original_stream_settings);
  return stream;
}

std::ostream& operator<<(std::ostream& stream,
                         const USNJournalEventRecord& record) {
  stream << "journal_record_version:\"" << record.journal_record_version
         << "\" ";

  stream << "drive_letter:\"" << record.drive_letter << "\" ";
  stream << "type:\"" << record.type << "\" ";
  stream << "usn:\"" << record.update_sequence_number << "\" ";
  stream << "parent_ref:\"" << record.parent_ref_number.str() << "\" ";
  stream << "ref:\"" << record.node_ref_number.str() << "\" ";

  std::tm local_time;
  localtime_s(&local_time, &record.record_timestamp);
  stream << "timestamp:\"" << std::put_time(&local_time, "%y-%m-%d %H:%M:%S")
         << "\" ";

  stream << "attributes:\"";

  bool add_separator = false;
  for (const auto& p : kWindowsFileAttributeMap) {
    const auto& bit = p.first;
    const auto& label = p.second;

    if ((record.attributes & bit) != 0) {
      if (add_separator) {
        stream << " | ";
      }

      stream << label;
      add_separator = true;
    }
  }

  stream << "\"";

  if (!record.name.empty()) {
    stream << " name:\"" << record.name << "\"";
  }

  return stream;
}
} // namespace osquery
