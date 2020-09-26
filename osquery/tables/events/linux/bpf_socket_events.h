/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/events/linux/bpf/bpfeventpublisher.h>

namespace osquery {

class BPFSocketEventSubscriber final : public EventSubscriber<BPFEventPublisher> {
 public:
  virtual ~BPFSocketEventSubscriber() override = default;
  virtual Status init() override;

  Status eventCallback(const ECRef& event_context,
                       const SCRef& subscription_context);

  // clang-format off
  [[deprecated("generateRow() does not have a unit test yet")]]
  // clang-format on
  static bool generateRow(Row& row, const ISystemStateTracker::Event& event);

  static std::vector<Row> generateRowList(
      const ISystemStateTracker::EventList& event_list);
};
} // namespace osquery
