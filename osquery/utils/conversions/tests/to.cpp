/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <unordered_map>

#include <gtest/gtest.h>

#include <osquery/utils/conversions/to.h>

namespace osquery {

class NonFailingConversionsTests : public testing::Test {};

enum class TestGreenColor {
  Green,
  Pine,
  Fern,
  Olive,
};

TEST_F(NonFailingConversionsTests, to_string_from_enum_class) {
  EXPECT_NE(std::string::npos,
            to<std::string>(TestGreenColor::Green).find("TestGreenColor[0]"));
  EXPECT_NE(std::string::npos,
            to<std::string>(TestGreenColor::Pine).find("TestGreenColor[1]"));
  EXPECT_NE(std::string::npos,
            to<std::string>(TestGreenColor::Fern).find("TestGreenColor[2]"));
}

enum class TestOrangeColor {
  Orange,
  Fire,
  Clay,
  Cider,
};

TEST_F(NonFailingConversionsTests, to_string_from_old_enum) {
  EXPECT_NE(
      std::string::npos,
      to<std::string>(TestOrangeColor::Orange).find("TestOrangeColor[0]"));
  EXPECT_NE(std::string::npos,
            to<std::string>(TestOrangeColor::Fire).find("TestOrangeColor[1]"));
  EXPECT_NE(std::string::npos,
            to<std::string>(TestOrangeColor::Clay).find("TestOrangeColor[2]"));
  EXPECT_NE(std::string::npos,
            to<std::string>(TestOrangeColor::Cider).find("TestOrangeColor[3]"));
}

} // namespace osquery
