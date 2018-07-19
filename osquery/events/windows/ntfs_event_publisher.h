/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <unordered_set>

#include <osquery/events.h>

#include "osquery/events/windows/usn_journal_reader.h"

namespace osquery {
/// The subscription context contains the list of paths the subscriber is
/// interested in
struct NTFSEventSubscriptionContext final : public SubscriptionContext {
 private:
  friend class FileEventPublisher;
};

using NTFSEventSubscriptionContextRef =
    std::shared_ptr<NTFSEventSubscriptionContext>;

/// A file change event context can contain many file change descriptors,
/// depending on how much data from the journal has been processed
struct NTFSEventContext final : public EventContext {
  /// This map contains the full paths for the references we found in
  /// the USN journal records
  std::unordered_map<USNFileReferenceNumber, std::string> ref_to_path_map;

  /// The list of events received from the USN journal
  std::vector<USNJournalEventRecord> event_list;
};

using NTFSEventContextRef = std::shared_ptr<NTFSEventContext>;

/// A USNJournalReaderInstance is an std::pair of the service and its associated
/// context structure
using USNJournalReaderInstance =
    std::pair<USNJournalReaderRef, USNJournalReaderContextRef>;

/// The NTFSEventPublisher configuration is just a list of drives we are
/// monitoring
using NTFSEventPublisherConfiguration = std::unordered_set<char>;

/// The file change publisher receives the raw events from the USNJournalReader
/// and processes them to emit file change events
class NTFSEventPublisher final
    : public EventPublisher<NTFSEventSubscriptionContext, NTFSEventContext> {
  DECLARE_PUBLISHER("ntfseventpublisher");

  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// If needed, this method spawns a new USNJournalReader service for the given
  /// volume
  void restartJournalReaderServices(std::unordered_set<char>& active_drives);

  /// Acquires new events from the reader service, firing new events to
  /// subscribers
  std::vector<USNJournalEventRecord> acquireEvents();

  /// Updates the components cache used for passive path resolution
  void updatePathComponentCache(
      const std::vector<USNJournalEventRecord>& event_list);

  /// Takes ownership of the given event list and dispatches them to the
  /// subscribers
  void takeEventsAndNotifySuscribers(
      std::vector<USNJournalEventRecord>& event_list);

  /// Reads the configuration, saving the list of drives that need to be
  /// monitored
  NTFSEventPublisherConfiguration readConfiguration();

  /// Builds a map (ref id -> path) used to dereference the paths in the event
  void buildEventPathMap(NTFSEventContextRef event_context);

  /// Attempts to fetch the path for the given referece number from the path
  /// resolution cache
  bool getPathFromResolutionCache(std::string& path,
                                  const USNFileReferenceNumber& ref);

  /// Attempts to resolve the path by using the cached path components
  bool resolvePathFromComponentsCache(std::string& path,
                                      const USNJournalEventRecord& record);

  /// Attempts to resolve the reference number into a full path
  Status resolvePathFromFileReferenceNumber(std::string& path,
                                            char drive_letter,
                                            const USNFileReferenceNumber& ref);

  /// Returns a HANDLE for the specified drive
  Status getDriveHandle(HANDLE& handle, char drive_letter);

  /// Releases the drive handle cache
  void releaseDriveHandleMap();

  /// Updates the path resolution cache
  void updatePathResolutionCache(const USNFileReferenceNumber& ref,
                                 const std::string& path);

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

// TODO(alessandro): write a test for this
/// Converts a USNFileReferenceNumber to a FILE_ID_DESCRIPTOR for the
/// OpenFileById Windows API
void GetNativeFileIdFromUSNReference(FILE_ID_DESCRIPTOR& file_id,
                                     const USNFileReferenceNumber& ref);
} // namespace osquery
