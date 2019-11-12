/**
 *  Copyright (c) 2019-present, osquery Foundation
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include <osquery/events.h>
#include <osquery/events/stringmap_encoder.hpp>
#include <osquery/utils/info/tool_type.h>

namespace osquery {

class StringMapEncoderTests : public ::testing::Test {
 protected:
  void SetUp() override {}
  void TearDown() override {}
};

const std::map<std::string, std::string> sm1 = {
    {"alpha", "beta"},
    {"uno", "1"},
    {"some_longer_named_key_goes_here", "blah blah blah blah blah"},
    {"minus", "-1"},
};
const size_t sm1StringLen = 75; // contact all strings of sm1

TEST_F(StringMapEncoderTests, data_size) {
  StringHash sh;
  size_t dataSize = CalcSimpleStringMapEncodeSize(sm1, sh);
  size_t expSize = sm1StringLen;
  expSize += 4 + 4 * 4; // data header (uint32_t) + field headers (uint32_t)

  EXPECT_EQ(expSize, dataSize);
}

TEST_F(StringMapEncoderTests, encode) {
  StringMapCoder encoder;
  std::string encodedBytes;
  bool status = encoder.encode(sm1, encodedBytes);
  EXPECT_FALSE(status);
  std::map<std::string, std::string> decodedMap;
  status = encoder.decode(decodedMap, encodedBytes);
  EXPECT_FALSE(status);
  EXPECT_EQ(4, decodedMap.size());
  for (auto& it : sm1) {
    std::string key = it.first;
    std::string value = it.second;
    EXPECT_EQ(value, decodedMap[key]);
  }
}

} // namespace osquery