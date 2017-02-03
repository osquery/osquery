/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/events.h>
#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/events/windows/windows_event_log.h"
#include "osquery/tests/test_util.h"

namespace osquery {

class WindowsEventLogTests : public testing::Test {};

TEST_F(WindowsEventLogTests, test_register_event_pub) {
  auto pub = std::make_shared<WindowsEventLogEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);
  EXPECT_TRUE(status.ok());

  // Make sure only one event type exists
  EXPECT_EQ(EventFactory::numEventPublishers(), 1U);
  // And deregister
  status = EventFactory::deregisterEventPublisher("windows_event_log");
  EXPECT_TRUE(status.ok());
}
}
