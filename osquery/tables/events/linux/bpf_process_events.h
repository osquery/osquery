/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/eventsubscriber.h>
#include <osquery/events/linux/bpf/bpf_process_event_publisher.h>

namespace osquery {

class BPFProcessEventSubscriber
    : public EventSubscriber<BPFProcessEventPublisher> {
 public:
  Status init() override;
  
  Status eventCallback(const ECRef& ec, const SCRef& sc);
  
  static bool generateRow(Row& row, const BPFProcessEvent& event);
  static std::vector<Row> generateRowList(
      const BPFProcessEventList& event_list);
  
 private:
  static std::string generateCmdlineColumn(const std::string& args);
  static std::string generateJsonCmdlineColumn(const std::string& args);
};

} // namespace osquery
