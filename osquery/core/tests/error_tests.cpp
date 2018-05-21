/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>
#include <osquery/error.h>

GTEST_TEST(ErrorTest, initialization) {
  auto error = osquery::Error("TestDomain", 32, "TestMessage");
  EXPECT_EQ(error.getUnderlyingError(), nullptr);
  EXPECT_EQ(error.getDomain(), "TestDomain");
  EXPECT_EQ(error.getErrorCode(), 32);
  EXPECT_EQ(error.getShortMessage(), "TestDomain 32");
  EXPECT_EQ(error.getFullMessage(), "TestDomain 32 (TestMessage)");
  EXPECT_TRUE(error == "TestDomain");
  EXPECT_TRUE(error == 32);
  EXPECT_TRUE(error == osquery::Error("TestDomain", 32));
}

GTEST_TEST(ErrorTest, recursive) {
  auto orignalError = std::shared_ptr<osquery::Error>(
      new osquery::Error("SuperDomain", 32, "SuperTestMessage"));
  auto error = osquery::Error("TestDomain", 55, "TestMessage", orignalError);
  EXPECT_NE(error.getUnderlyingError(), nullptr);
  EXPECT_EQ(error.getShortMessageRecursive(),
            "TestDomain 55 <- SuperDomain 32");
  EXPECT_EQ(error.getFullMessageRecursive(),
            "TestDomain 55 (TestMessage) <- SuperDomain 32 (SuperTestMessage)");
}
