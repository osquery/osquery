/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/utils/base64.h>

namespace osquery {

class Base64Tests : public testing::Test {};

TEST_F(Base64Tests, test_base64) {
  std::string_view unencoded("HELLO");
  auto encoded = base64::encode(unencoded);
  EXPECT_NE(encoded.size(), 0U);

  // Decode input as a string_view.
  auto unencoded2 = base64::decode(std::string_view(encoded));
  EXPECT_EQ(unencoded, unencoded2);

  // Skip line breaks while decoding.
  std::string encoded_with_line_breaks = "\n" + encoded + "\r\n==";
  auto unencoded3 = base64::decode(encoded_with_line_breaks);
  EXPECT_EQ(unencoded3, unencoded2);

  // Check that the string_view input with line breaks still can be decoded.
  auto unencoded4 = base64::decode(std::string_view(encoded_with_line_breaks));
  EXPECT_EQ(unencoded4, unencoded2);

  // Decode rvalue reference from the encoded string.
  auto unencoded5 = base64::decode(std::move(encoded_with_line_breaks));
  EXPECT_EQ(unencoded5, unencoded2);
}

} // namespace osquery
