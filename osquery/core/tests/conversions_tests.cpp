/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/system.h>

#include "osquery/core/conversions.h"

#include "osquery/tests/test_util.h"

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

TEST_F(ConversionsTests, test_buffer_sha1) {
  std::string test = "test\n";
  EXPECT_EQ("4e1243bd22c66e76c2ba9eddc1f91394e57f9f83",
            getBufferSHA1(test.c_str(), test.size()));
}

TEST_F(ConversionsTests, test_json_array) {
  auto doc = JSON::newArray();

  {
    auto line = doc.getObject();
    size_t value = 10_sz;
    doc.add("key", value, line);
    doc.push(line);
  }

  std::string result;
  EXPECT_TRUE(doc.toString(result));

  std::string expected = "[{\"key\":10}]";
  EXPECT_EQ(expected, result);
}

TEST_F(ConversionsTests, test_json_object) {
  auto doc = JSON::newObject();

  {
    size_t value = 10_sz;
    doc.add("key", value);
  }

  std::string result;
  EXPECT_TRUE(doc.toString(result));

  std::string expected = "{\"key\":10}";
  EXPECT_EQ(expected, result);
}

TEST_F(ConversionsTests, test_json_strings) {
  auto doc = JSON::newObject();

  {
    std::string value("value");
    doc.addCopy("key", value);
  }

  std::string value2("value2");
  doc.addRef("key2", value2);

  std::string result;
  EXPECT_TRUE(doc.toString(result));

  std::string expected = "{\"key\":\"value\",\"key2\":\"value2\"}";
  EXPECT_EQ(expected, result);
}
}
