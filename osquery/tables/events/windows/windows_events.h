/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <ctime>

#include <osquery/events/windows/windowseventlogparser.h>
#include <osquery/events/windows/windowseventlogpublisher.h>

namespace pt = boost::property_tree;

namespace osquery {
class WindowsEventSubscriber
    : public EventSubscriber<WindowsEventLogPublisher> {
 public:
  Status init() override;
  virtual ~WindowsEventSubscriber() override;

  Status Callback(const ECRef& event, const SCRef& subscription);

  static void generateRow(Row& row, const WELEvent& windows_event);
};
} // namespace osquery
