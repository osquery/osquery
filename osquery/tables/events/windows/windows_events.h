/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <ctime>

#include <osquery/events/eventsubscriber.h>
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
