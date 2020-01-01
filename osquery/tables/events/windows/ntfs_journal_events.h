/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <unordered_map>
#include <unordered_set>

#include "osquery/events/windows/ntfs_event_publisher.h"

namespace osquery {
/// Subscriber for file change events
class NTFSEventSubscriber final : public EventSubscriber<NTFSEventPublisher> {
  /// Returns true if the specified event is a write operation
  bool isWriteOperation(const USNJournalEventRecord::Type& type);

  /// Returns true if the specified event should be emitted
  bool shouldEmit(const SCRef& sc, const NTFSEventRecord& event);

  /// Generates a row from the specified event
  Row generateRowFromEvent(const NTFSEventRecord& event);

 public:
  /// Constructor
  NTFSEventSubscriber();

  /// Destructor
  virtual ~NTFSEventSubscriber();

  /// Initialization routine
  Status init() override;

  /// Configuration callback; may be called more than once
  void configure() override;

  /// Events are received from the publisher through this callback
  Status Callback(const ECRef& ec, const SCRef& sc);
};

/// A simple vector of strings
using StringList = std::vector<std::string>;

/// Processes the configuration
void processConfiguration(const NTFSEventSubscriptionContextRef context,
                          const StringList& access_categories,
                          StringList& include_paths,
                          StringList& exclude_paths);
} // namespace osquery
