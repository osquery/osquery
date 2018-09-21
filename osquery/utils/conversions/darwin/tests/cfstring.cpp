/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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
