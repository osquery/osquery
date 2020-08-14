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

#include <osquery/utils/conversions/darwin/cfstring.h>

namespace osquery {

class ConversionsTests : public testing::Test {};

TEST_F(ConversionsTests, stringFromCFString) {
  auto const in_str = std::string{u8"空間"};
  auto const cf_string_ref =
      CFStringCreateWithBytes(kCFAllocatorDefault,
                              reinterpret_cast<const UInt8*>(in_str.data()),
                              in_str.size(),
                              kCFStringEncodingUTF8,
                              false);
  auto out_str = stringFromCFString(cf_string_ref);
  EXPECT_EQ(in_str, out_str);
}

} // namespace osquery
