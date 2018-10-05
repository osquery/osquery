/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#ifdef __linux__

#include <map>
#include <set>
#include <string>

#include <gtest/gtest.h>

#include "osquery/tables/events/linux/selinux_events.h"

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

#endif
