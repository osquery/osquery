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

#include <osquery/utils/conversions/trim.h>

namespace osquery {

class TrimConversionsTests : public testing::Test {};

struct TrimStringTestData {
  std::string test_string;
  std::string expected_string;
};

std::vector<TrimStringTestData> generateTrimStringTestData() {
  TrimStringTestData s1;
  s1.test_string = "a bc";
  s1.expected_string = "a bc";

  TrimStringTestData s2;
  s2.test_string = "  a bc";
  s2.expected_string = "a bc";

  TrimStringTestData s3;

  TrimStringTestData s4;
  s4.test_string = "a b c  ";
  s4.expected_string = "a b c";

  TrimStringTestData s5;
  s5.test_string = "  a b c  ";
  s5.expected_string = "a b c";

  TrimStringTestData s6;
  s6.test_string = "abc";
  s6.expected_string = "abc";

  TrimStringTestData s7;
  s7.test_string = "\tabc\t";
  s7.expected_string = "abc";

  TrimStringTestData s8;
  s8.test_string = "\nabc\n";
  s8.expected_string = "abc";

  TrimStringTestData s9;
  s9.test_string = "\rabc\r";
  s9.expected_string = "abc";

  TrimStringTestData s10;
  s10.test_string = "\fabc\f";
  s10.expected_string = "abc";

  TrimStringTestData s11;
  s11.test_string = "\vabc\v";
  s11.expected_string = "abc";

  TrimStringTestData s12;
  s12.test_string = "   ";

  return {s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12};
}

TEST_F(TrimConversionsTests, test_trim) {
  for (const auto& i : generateTrimStringTestData()) {
    EXPECT_EQ(trim(i.test_string), i.expected_string);
  }
}

} // namespace osquery
