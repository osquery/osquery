/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/events/linux/bpfprocesseventspublisher.h>

namespace osquery {

class BPFProcessEventsSubscriber final
    : public EventSubscriber<BPFProcessEventsPublisher> {
 public:
  virtual ~BPFProcessEventsSubscriber() override = default;
  virtual Status init() override;

  Status eventCallback(const ECRef& event_context,
                       const SCRef& subscription_context);
};
} // namespace osquery
