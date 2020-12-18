/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <unordered_set>

#include "osquery/events/windows/usn_journal_reader.h"
#include <osquery/events/eventpublisher.h>

namespace osquery {
/// The subscription context contains the list of paths the subscriber is
/// interested in
struct NTFSEventSubscriptionContext : public SubscriptionContext {
  /// The category that this event originated from.
  std::string category;

  /// Collection of paths that should only be included during write or
  /// delete operations.
  std::unordered_set<std::string> write_paths;

  /// Collection of file reference numbers that should only be included
  /// during write or delete operations.
  std::unordered_set<USNFileReferenceNumber> write_frns;

  /// Collection of paths that must always be included (even for reads).
  std::unordered_set<std::string> access_paths;

  /// Collection of file reference numbers that must always be included
  /// (even for reads).
  std::unordered_set<USNFileReferenceNumber> access_frns;

 private:
  friend class FileEventPublisher;
};

using NTFSEventSubscriptionContextRef =
    std::shared_ptr<NTFSEventSubscriptionContext>;

/// A single NTFS event record
struct NTFSEventRecord final {
  /// Event type
  USNJournalEventRecord::Type type;

  /// Path
  std::string path;

  /// Previous path (only valid for rename operations)
  std::string old_path;

  /// Record timestamp
  std::time_t record_timestamp{0U};

  /// Node attributes
  DWORD attributes;

  /// Update sequence number of the journal record
  USN update_sequence_number{0U};

  /// Ordinal for the file or directory referenced by this record
  USNFileReferenceNumber node_ref_number;

  /// Ordinal for the directory containing the file or directory referenced
  USNFileReferenceNumber parent_ref_number;

  /// Drive letter
  char drive_letter{0U};

  /// If true, this event is partial; it means that we could only get
  /// the file or folder name inside path or old_path
  bool partial{false};

  NTFSEventRecord(const USNJournalEventRecord& rec)
      : type(rec.type),
        record_timestamp(rec.record_timestamp),
        attributes(rec.attributes),
        update_sequence_number(rec.update_sequence_number),
        node_ref_number(rec.node_ref_number),
        parent_ref_number(rec.parent_ref_number),
        drive_letter(rec.drive_letter) {}
};

/// This structure is used to save volume handles and reference ids
struct VolumeData final {
  /// Volume handle, used to perform journal queries
  HANDLE volume_handle;

  /// Root folder handle
  HANDLE root_folder_handle;

  /// This is the root folder reference number; we need it when walking
  /// the file reference tree
  USNFileReferenceNumber root_ref;
};

static_assert(std::is_move_constructible<NTFSEventRecord>::value,
              "not move constructible");

/// A file change event context can contain many file change descriptors,
/// depending on how much data from the journal has been processed
struct NTFSEventContext final : public EventContext {
  /// The list of events received from the USN journal
  std::vector<NTFSEventRecord> event_list;
};

using NTFSEventContextRef = std::shared_ptr<NTFSEventContext>;

/// The ParentFRNCache maps parent FRNs to directory names
using ParentFRNCache = std::unordered_map<USNFileReferenceNumber, std::string>;

/// This structure describes a running USNJournalReader instance
struct USNJournalReaderInstance final {
  /// The reader service
  USNJournalReaderRef reader;

  /// The shared context
  USNJournalReaderContextRef context;

  /// This cache contains a mapping from parent FRN to directory name.
  ParentFRNCache parent_frn_cache;

  /// This map is used to merge the rename records (old name and new name) into
  /// a single event. It is ordered so that we can delete data starting from the
  /// oldest entries
  std::map<USNFileReferenceNumber, USNJournalEventRecord> rename_path_mapper;
};

/// The NTFSEventPublisher configuration is just a list of drives we are
/// monitoring
using NTFSEventPublisherConfiguration = std::unordered_set<char>;

/// The file change publisher receives the raw events from the USNJournalReader
/// and processes them to emit file change events
class NTFSEventPublisher final
    : public EventPublisher<NTFSEventSubscriptionContext, NTFSEventContext> {
  DECLARE_PUBLISHER("ntfs_event_publisher");

  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d_;

  /// If needed, this method spawns a new USNJournalReader service for the given
  /// volume
  void restartJournalReaderServices(std::unordered_set<char>& active_drives);

  /// Acquires new events from the reader service, firing new events to
  /// subscribers
  std::vector<USNJournalEventRecord> acquireJournalRecords();

  /// Reads the configuration, saving the list of drives that need to be
  /// monitored
  NTFSEventPublisherConfiguration readConfiguration();

  /// Attempts to get the full path for the given file reference.
  Status getPathFromReferenceNumber(std::string& path,
                                    char drive_letter,
                                    const USNFileReferenceNumber& ref);

  /// Attempts to get the full path for `basename` via its parent FRN.
  Status getPathFromParentFRN(std::string& path,
                              ParentFRNCache& parent_frn_cache,
                              char drive_letter,
                              const std::string& basename,
                              const USNFileReferenceNumber& ref);

  /// Returns a VolumeData structure containing the volume handle and the
  /// root folder reference number
  Status getVolumeData(VolumeData& volume, char drive_letter);

  /// Releases the drive handle cache
  void releaseDriveHandleMap();

 public:
  /// Constructor
  NTFSEventPublisher();

  /// Destructor
  virtual ~NTFSEventPublisher();

  /// Initializes the publisher
  Status setUp() override;

  /// Called during startup and every time the configuration is reloaded
  void configure() override;

  /// Publisher's entry point
  Status run() override;

  /// Clean up routine
  void tearDown() override;
};

/// Converts a USNFileReferenceNumber to a FILE_ID_DESCRIPTOR for the
/// OpenFileById Windows API
void GetNativeFileIdFromUSNReference(FILE_ID_DESCRIPTOR& file_id,
                                     const USNFileReferenceNumber& ref);
} // namespace osquery
