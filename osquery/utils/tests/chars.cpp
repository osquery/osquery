/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <gtest/gtest.h>

#include <osquery/utils/chars.h>

namespace osquery {

class ConversionsTests : public testing::Test {};

TEST_F(ConversionsTests, test_ascii_true) {
  std::string unencoded = "HELLO";
  auto result = isPrintable(unencoded);
  EXPECT_TRUE(result);
}

TEST_F(ConversionsTests, test_ascii_false) {
  std::string unencoded = "こんにちは";
  auto result = isPrintable(unencoded);
  EXPECT_FALSE(result);
}

TEST_F(ConversionsTests, test_unicode_unescape) {
  std::vector<std::pair<std::string, std::string>> conversions = {
      std::make_pair("\\u0025hi", "%hi"),
      std::make_pair("hi\\u0025", "hi%"),
      std::make_pair("\\uFFFFhi", "\\uFFFFhi"),
      std::make_pair("0000\\u", "0000\\u"),
      std::make_pair("hi", "hi"),
      std::make_pair("c:\\\\users\\\\obelisk\\\\file.txt",
                     "c:\\\\users\\\\obelisk\\\\file.txt"),
      std::make_pair("Edge case test\\", "Edge case test\\"),
      std::make_pair("Edge case test two\\\\", "Edge case test two\\\\"),
  };

  for (const auto& test : conversions) {
    EXPECT_EQ(unescapeUnicode(test.first), test.second);
  }
}

} // namespace osquery
