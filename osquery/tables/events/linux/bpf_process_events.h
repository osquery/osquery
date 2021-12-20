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

  static bool generateExecRow(Row& row,
                              const ISystemStateTracker::Event& event);

  static bool generateCapCapableRow(Row& row,
                                    const ISystemStateTracker::Event& event);

  static bool generatePtraceRow(Row& row,
                                const ISystemStateTracker::Event& event);

  static bool generateInitModuleRow(Row& row,
                                    const ISystemStateTracker::Event& event);

  static bool generateFinitModuleRow(Row& row,
                                     const ISystemStateTracker::Event& event);

  static bool generateIoctlRow(Row& row,
                               const ISystemStateTracker::Event& event);

  static bool generateDeleteModuleRow(Row& row,
                                      const ISystemStateTracker::Event& event);

  static std::vector<Row> generateRowList(
      const ISystemStateTracker::EventList& event_list);

  static bool initializeEventRow(Row& row,
                                 const ISystemStateTracker::Event& event);

  static std::string generateExecData(const std::vector<std::string>& argv);

  static std::string generateExecJsonData(const std::vector<std::string>& argv);

  static std::string generateCapCapableData(
      const ISystemStateTracker::Event::CapableData& data);

  static std::string generateCapCapableJsonData(
      const ISystemStateTracker::Event::CapableData& data);

  static std::string generatePtraceData(
      const ISystemStateTracker::Event::PtraceData& data);

  static std::string generatePtraceJsonData(
      const ISystemStateTracker::Event::PtraceData& data);

  static std::string generateInitModuleData(
      const ISystemStateTracker::Event::InitModuleData& data);

  static std::string generateInitModuleJsonData(
      const ISystemStateTracker::Event::InitModuleData& data);

  static std::string generateFinitModuleData(
      const ISystemStateTracker::Event::FinitModuleData& data);

  static std::string generateFinitModuleJsonData(
      const ISystemStateTracker::Event::FinitModuleData& data);

  static std::string generateIoctlData(
      const ISystemStateTracker::Event::IoctlData& data);

  static std::string generateIoctlJsonData(
      const ISystemStateTracker::Event::IoctlData& data);

  static std::string generateDeleteModuleData(
      const ISystemStateTracker::Event::DeleteModuleData& data);

  static std::string generateDeleteModuleJsonData(
      const ISystemStateTracker::Event::DeleteModuleData& data);
};

} // namespace osquery
