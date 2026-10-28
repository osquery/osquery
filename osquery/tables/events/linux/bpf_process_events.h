/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/eventsubscriber.h>
#include <osquery/events/linux/bpf/bpfeventpublisher.h>

namespace osquery {

class BPFProcessEventSubscriber final
    : public EventSubscriber<BPFEventPublisher> {
 public:
  virtual ~BPFProcessEventSubscriber() override = default;
  virtual Status init() override;

  Status eventCallback(const ECRef& event_context,
                       const SCRef& subscription_context);

  static bool generateRow(Row& row, const ISystemStateTracker::Event& event);

  static std::vector<Row> generateRowList(
      const ISystemStateTracker::EventList& event_list);

  static std::string generateCmdlineColumn(
      const std::vector<std::string>& argv);

  static std::string generateJsonCmdlineColumn(
      const std::vector<std::string>& argv);
};

} // namespace osquery
