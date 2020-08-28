/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <map>
#include <set>
#include <string>

#include <gtest/gtest.h>

#include <osquery/events/linux/selinux_events.h>
#include <osquery/tables/events/linux/selinux_events.h>

namespace osquery {
class SELinuxEventsTests : public testing::Test {};

TEST_F(SELinuxEventsTests, record_type_labels) {
  EXPECT_EQ(kSELinuxRecordLabels.size(), kSELinuxEventList.size());

  for (auto event_type : kSELinuxEventList) {
    auto label_it = kSELinuxRecordLabels.find(event_type);
    EXPECT_TRUE(label_it != kSELinuxRecordLabels.end());
  }
}
} // namespace osquery
