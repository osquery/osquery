/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <ctime>

#include <osquery/events/windows/windowseventlogpublisher.h>

namespace pt = boost::property_tree;

namespace osquery {
class WindowsEventSubscriber
    : public EventSubscriber<WindowsEventLogPublisher> {
 public:
  Status init() override;
  virtual ~WindowsEventSubscriber() override;

  Status Callback(const ECRef& event, const SCRef& subscription);

  struct Event final {
    std::time_t osquery_time{0U};
    std::string datetime;

    std::string source;
    std::string provider_name;
    std::string provider_guid;

    std::int64_t event_id{0U};
    std::int64_t task_id{0U};
    std::int64_t level{0U};

    std::string keywords;
    std::string data;
  };

  static Status processEventObject(
      Event& windows_event, const boost::property_tree::ptree& event_object);

  static void generateRow(Row& row, const Event& windows_event);
};
} // namespace osquery
