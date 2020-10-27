/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <algorithm>
#include <atomic>
#include <ctime>
#include <memory>
#include <ostream>
#include <sstream>
#include <vector>

#include <boost/functional/hash.hpp>

#include <osquery/dispatcher/dispatcher.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <winioctl.h>


namespace osquery {

/// The USN File Reference Number uniquely identifies a file within a volume
struct USNFileReferenceNumber {
  std::vector<std::uint8_t> data;

  USNFileReferenceNumber() : data() {}
  explicit USNFileReferenceNumber(std::uint64_t val) {
    data.resize(sizeof(val));
    std::memcpy(data.data(), &val, sizeof(val));
  }

  void operator=(DWORDLONG val) {
    static_assert(sizeof(val) == 8, "unexpected assignment size");
    data.resize(sizeof(val));
    std::memcpy(data.data(), &val, sizeof(val));
  }
  void operator=(FILE_ID_128 val) {
    static_assert(sizeof(val.Identifier) == 16, "unexpected assignment size");
    data.resize(sizeof(val.Identifier));
    std::memcpy(data.data(), &val.Identifier, sizeof(val.Identifier));
  }
  void operator=(GUID val) {
    static_assert(sizeof(val) == 16, "unexpected assignment size");
    data.resize(sizeof(val));
    std::memcpy(data.data(), &val, sizeof(val));
  }

  bool operator==(const USNFileReferenceNumber& rhs) const;
  bool operator!=(const USNFileReferenceNumber& rhs) const;
  bool operator<(const USNFileReferenceNumber& rhs) const;

  std::string str() const;
};

/// Event record
struct USNJournalEventRecord final {
  /// Supported event types
  enum class Type {
    AttributesChange,
    ExtendedAttributesChange,
    DirectoryCreation,
    FileWrite,
    DirectoryOverwrite,
    FileOverwrite,
    DirectoryTruncation,
    FileTruncation,
    TransactedDirectoryChange,
    TransactedFileChange,
    FileCreation,
    DirectoryDeletion,
    FileDeletion,
    DirectoryLinkChange,
    FileLinkChange,
    DirectoryIndexingSettingChange,
    FileIndexingSettingChange,
    DirectoryIntegritySettingChange,
    FileIntegritySettingChange,
    AlternateDataStreamWrite,
    AlternateDataStreamOverwrite,
    AlternateDataStreamTruncation,
    AlternateDataStreamChange,
    DirectoryObjectIdChange,
    FileObjectIdChange,
    DirectoryRename_NewName,
    FileRename_NewName,
    DirectoryRename_OldName,
    FileRename_OldName,
    ReparsePointChange,
    DirectorySecurityAttributesChange,
    FileSecurityAttributesChange
  };

  /// Event type
  Type type;

  /// The drive letter is used to resolve reference numbers to path. It is also
  /// useful for debugging
  char drive_letter{0U};

  /// Record version; mostly for debug
  size_t journal_record_version;

  /// The sequence number that identifies this change in the journal
  USN update_sequence_number;

  /// Reference number for this node
  USNFileReferenceNumber node_ref_number;

  /// Reference number for the parent folder
  USNFileReferenceNumber parent_ref_number;

  /// Record timestamp
  std::time_t record_timestamp;

  /// Node attributes
  DWORD attributes;

  /// File name
  std::string name;
};

static_assert(std::is_move_constructible<USNJournalEventRecord>::value,
              "not move constructible");

/// This map is used to deduplicate record types; we are using an ordered
/// container in order to easily drop the oldest entries when limiting
/// the amount of memory used
using USNPerFileLastRecordType =
    std::map<USNFileReferenceNumber, USNJournalEventRecord::Type>;

/// Used to convert a Windows file attribute bit to its description
extern const std::unordered_map<int, std::string> kWindowsFileAttributeMap;

/// Used to convert an event record type to its description
extern const std::unordered_map<USNJournalEventRecord::Type, std::string>
    kNTFSEventToStringMap;

/// Contains data shared between the USNJournalReader service and the
/// FileChangePublisher
struct USNJournalReaderContext final {
  /// This is the letter where the volume has been mounted to
  char drive_letter{0U};

  /// This flag is set when the reader is no longer needed (i.e.: mount point
  /// removed, or subscription no longer useful)
  std::atomic_bool terminate{false};

  /// List of records ready for consumption
  std::vector<USNJournalEventRecord> processed_record_list;

  /// Mutex for the list of processed records
  Mutex processed_records_mutex;

  /// This is used to wake up the publisher
  ConditionVariable processed_records_cv;
};

using USNJournalReaderContextRef = std::shared_ptr<USNJournalReaderContext>;

/// The USN Journal Reader is a service (thread) dedicated to asynchronously
/// read update records from the operating system
class USNJournalReader final : public InternalRunnable {
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d_;

  /// Initialization routine
  Status initialize();

  /// Acquires the journal records from the volume
  Status acquireRecords();

  /// Processes the records saved by acquireRecords
  Status processAcquiredRecords(
      std::vector<USNJournalEventRecord>& record_list);

  /// Sends the given record vector to the publisher
  void dispatchEventRecords(
      const std::vector<USNJournalEventRecord>& record_list);

 protected:
  /// Service entry point
  virtual void start() override;

  /// Stop callback; cleanup is performed here
  virtual void stop() override;

 public:
  /// Constructor; the context structure is shared with the FileChangePublisher
  USNJournalReader(USNJournalReaderContextRef journal_reader_context);

  /// Destructor
  virtual ~USNJournalReader();

  /// Decompresses the record by generating distinct events
  static Status DecompressRecord(
      std::vector<USNJournalEventRecord>& new_records,
      const USNJournalEventRecord& base_record,
      DWORD journal_record_reason,
      USNPerFileLastRecordType& per_file_last_record_type_map);

  /// Processes a single USN record, appending the output to the given vector
  static Status ProcessAndAppendUSNRecord(
      std::vector<USNJournalEventRecord>& record_list,
      const USN_RECORD* record,
      USNPerFileLastRecordType& per_file_last_record_type_map,
      char drive_letter);
};

using USNJournalReaderRef = std::shared_ptr<USNJournalReader>;

/// Converts our USNFileReferenceNumber type to the native format
void GetNativeFileIdFromUSNReference(FILE_ID_DESCRIPTOR& file_id,
                                     const USNFileReferenceNumber& ref);

namespace USNParsers {
/// Acquires the update sequence number from the record
bool GetUpdateSequenceNumber(USN& usn, const USN_RECORD* record);

/// Acquires the file reference number for the node
bool GetFileReferenceNumber(USNFileReferenceNumber& ref_number,
                            const USN_RECORD* record);

/// Acquires the file reference number for the parent node
bool GetParentFileReferenceNumber(USNFileReferenceNumber& ref_number,
                                  const USN_RECORD* record);

/// Acquires the record timestamp
bool GetTimeStamp(std::time_t& timestamp, const USN_RECORD* record);

/// Acquires the file attribute bits from the record
bool GetAttributes(DWORD& attributes, const USN_RECORD* record);

/// Acquires the `reason` DWORD containing a bit for each event type
bool GetReason(DWORD& reason, const USN_RECORD* record);

/// Converts the given `reason` bit into the internal record type
bool GetEventType(USNJournalEventRecord::Type& type,
                  DWORD reason_bit,
                  DWORD journal_file_attributes);

/// Acquires the string buffer from the record
bool GetEventString(std::string& buffer, const USN_RECORD* record);
} // namespace USNParsers

/// Prints the given record type
std::ostream& operator<<(std::ostream& stream,
                         const USNJournalEventRecord::Type& type);

/// Prints the given USN file reference number
std::ostream& operator<<(std::ostream& stream,
                         const USNFileReferenceNumber& ref);

/// Prints the given journal event record
std::ostream& operator<<(std::ostream& stream,
                         const USNJournalEventRecord& record);
} // namespace osquery

namespace std {
template <>
struct hash<osquery::USNFileReferenceNumber> {
  std::size_t operator()(const osquery::USNFileReferenceNumber& ref) const {
    return boost::hash_range(ref.data.begin(), ref.data.end());
  }
};
} // namespace std
