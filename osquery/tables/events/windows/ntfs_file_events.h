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

#include "osquery/events/windows/ntfs_event_publisher.h"

namespace osquery {
/// Subscriber for file change events
class NTFSEventSubscriber final : public EventSubscriber<NTFSEventPublisher> {
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

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
} // namespace osquery
