/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/ev2/manager.h>
#include <osquery/ev2/tests/utils.h>

#include <gtest/gtest.h>

namespace osquery {
namespace ev2 {
namespace {

class ManagerTests : public testing::Test {};

TEST_F(ManagerTests, test_register_and_bind) {
  EventManager em;
  auto sub = std::make_shared<NullSubscription>("test");
  auto pub = std::make_shared<NullPublisher>("test");

  EXPECT_FALSE(em.bind(sub));

  em.registerPublisher(pub);

  EXPECT_TRUE(em.bind(sub));
}

} // namespace
} // namespace ev2
} // namespace osquery
