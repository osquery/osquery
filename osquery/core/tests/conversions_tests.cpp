/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/flags.h>

#include "osquery/core/conversions.h"

#include "osquery/core/test_util.h"

#define EXPECT_WITHIN_INCLUSIVE(lower, upper, val)                     \
  do {                                                                 \
    EXPECT_PRED_FORMAT2(::testing::internal::CmpHelperGE, val, lower); \
    EXPECT_PRED_FORMAT2(::testing::internal::CmpHelperLE, val, upper); \
  } while (0)

namespace osquery {

DECLARE_bool(utc);

class ConversionsTests : public testing::Test {};

class Foobar {};

TEST_F(ConversionsTests, test_conversion) {
  boost::shared_ptr<Foobar> b1 = boost::make_shared<Foobar>();
  std::shared_ptr<Foobar> s1 = boost_to_std_shared_ptr(b1);
  EXPECT_EQ(s1.get(), b1.get());

  std::shared_ptr<Foobar> s2 = std::make_shared<Foobar>();
  boost::shared_ptr<Foobar> b2 = std_to_boost_shared_ptr(s2);
  EXPECT_EQ(s2.get(), b2.get());
}

TEST_F(ConversionsTests, test_utc) {
  auto utc = FLAGS_utc;
  FLAGS_utc = false;
  auto t1 = getUnixTime();
  auto at1 = std::time(nullptr);
  EXPECT_WITHIN_INCLUSIVE(t1 - 10U, t1 + 10, static_cast<size_t>(at1));

  FLAGS_utc = true;
  auto t2 = getUnixTime();
  auto rt2 = std::time(nullptr);
  auto at2 = std::mktime(std::gmtime(&rt2));
  EXPECT_WITHIN_INCLUSIVE(t2 - 10, t2 + 10, static_cast<size_t>(at2));
  FLAGS_utc = utc;
}

TEST_F(ConversionsTests, test_base64) {
  std::string unencoded = "HELLO";
  auto encoded = base64Encode(unencoded);
  EXPECT_NE(encoded.size(), 0U);

  auto unencoded2 = base64Decode(encoded);
  EXPECT_EQ(unencoded, unencoded2);
}

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
  };

  for (const auto& test : conversions) {
    EXPECT_EQ(unescapeUnicode(test.first), test.second);
  }
}

TEST_F(ConversionsTests, test_split) {
  for (const auto& i : generateSplitStringTestData()) {
    EXPECT_EQ(split(i.test_string), i.test_vector);
  }
}

TEST_F(ConversionsTests, test_join) {
  std::vector<std::string> content = {
      "one", "two", "three",
  };
  EXPECT_EQ(join(content, ", "), "one, two, three");
}

TEST_F(ConversionsTests, test_split_occurences) {
  std::string content = "T: 'S:S'";
  std::vector<std::string> expected = {
      "T", "'S:S'",
  };
  EXPECT_EQ(split(content, ":", 1), expected);
}
}
