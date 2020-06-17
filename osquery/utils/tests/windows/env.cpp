/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <boost/optional.hpp>
#include <gtest/gtest.h>

#include <osquery/utils/system/env.h>

namespace osquery {

class WindowsEnvTests : public testing::Test {};

TEST_F(WindowsEnvTests, test_expandEnvString) {
  // Environment strings larger than 32K can't be expanded by the Windows API.
  const auto& big = std::string(32769, 'A');
  EXPECT_EQ(expandEnvString(big), boost::none);

  const auto& windir = getEnvVar("WINDIR");
  EXPECT_TRUE(windir);
  EXPECT_EQ(*expandEnvString("%WINDIR%"), *windir);

  // Multiple expansions are handled correctly
  EXPECT_EQ(*expandEnvString("%WINDIR% %WINDIR%"), *windir + " " + *windir);
}

TEST_F(WindowsEnvTests, test_splitArgs) {
  const auto& args = splitArgs("\"C:\\Program Files\\Foo\" bar baz");
  EXPECT_TRUE(args);

  EXPECT_EQ(args.get().size(), 3);
  EXPECT_EQ(args.get().at(0), "C:\\Program Files\\Foo");
  EXPECT_EQ(args.get().at(1), "bar");
  EXPECT_EQ(args.get().at(2), "baz");
}

} // namespace osquery
