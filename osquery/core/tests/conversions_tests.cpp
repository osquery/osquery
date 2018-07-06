/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <cstdint>
#include <string>

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
      std::make_pair("c:\\\\users\\\\obelisk\\\\file.txt",
                     "c:\\\\users\\\\obelisk\\\\file.txt"),
      std::make_pair("Edge case test\\", "Edge case test\\"),
      std::make_pair("Edge case test two\\\\", "Edge case test two\\\\"),
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
  EXPECT_EQ(split(content, ':', 1), expected);
}

TEST_F(ConversionsTests, test_buffer_sha1) {
  std::string test = "test\n";
  EXPECT_EQ("4e1243bd22c66e76c2ba9eddc1f91394e57f9f83",
            getBufferSHA1(test.c_str(), test.size()));
}

TEST_F(ConversionsTests, test_json_array) {
  auto doc = JSON::newArray();

  {
    auto obj = doc.getObject();
    size_t value = 10_sz;
    doc.add("key", value, obj);
    int value2 = -10;
    doc.add("key2", value2, obj);
    doc.push(obj);
  }

  size_t value = 11_sz;
  doc.push(value);

  std::string result;
  EXPECT_TRUE(doc.toString(result));

  std::string expected = "[{\"key\":10,\"key2\":-10},11]";
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

TEST_F(ConversionsTests, test_json_from_string) {
  std::string json = "{\"key\":\"value\",\"key2\":{\"key3\":3}}";
  auto doc = JSON::newObject();

  EXPECT_TRUE(doc.fromString(json).ok());

  std::string result;
  EXPECT_TRUE(doc.toString(result));
  EXPECT_EQ(json, result);

  json += ';';
  EXPECT_FALSE(doc.fromString(json).ok());
}

TEST_F(ConversionsTests, test_json_from_string_error) {
  std::string json = "{\"key\":\"value\",\"key2\":{\"key3\":'error'}}";
  auto doc = JSON::newObject();
  auto s = doc.fromString(json);
  EXPECT_FALSE(s.ok());
  EXPECT_EQ(s.getMessage(), "Cannot parse JSON: Invalid value. Offset: 30");
}

TEST_F(ConversionsTests, test_json_add_object) {
  std::string json = "{\"key\":\"value\", \"key2\":{\"key3\":[3,2,1]}}";
  auto doc = JSON::newObject();

  ASSERT_TRUE(doc.fromString(json));
  auto doc2 = JSON::newObject();
  doc2.add("key2", doc.doc()["key2"]);
  EXPECT_TRUE(doc2.doc().HasMember("key2"));
  EXPECT_TRUE(doc2.doc()["key2"].IsObject());
  EXPECT_TRUE(doc2.doc()["key2"].HasMember("key3"));

  auto doc3 = JSON::newFromValue(doc.doc()["key2"]);
  ASSERT_TRUE(doc3.doc().IsObject());
  EXPECT_TRUE(doc3.doc().HasMember("key3"));

  auto doc4 = JSON::newArray();
  auto arr = doc4.getArray();
  doc4.copyFrom(doc.doc()["key2"]["key3"], arr);
  doc4.push(arr);

  std::string expected = "[[3,2,1]]";
  std::string output;
  ASSERT_TRUE(doc4.toString(output).ok());
  EXPECT_EQ(expected, output);
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

TEST_F(ConversionsTests, test_json_strings_array) {
  auto doc = JSON::newObject();

  {
    auto arr = doc.getArray();
    std::string value("value");
    doc.pushCopy(value, arr);
    doc.add("array", arr);
  }

  std::string result;
  EXPECT_TRUE(doc.toString(result));
  std::string expected = "{\"array\":[\"value\"]}";
  EXPECT_EQ(expected, result);
}

TEST_F(ConversionsTests, test_json_duplicate_keys) {
  auto doc = JSON::newObject();

  size_t value = 10_sz;
  doc.add("key", value);
  value = 11_sz;
  doc.add("key", value);

  std::string result;
  EXPECT_TRUE(doc.toString(result));

  std::string expected = "{\"key\":11}";
  EXPECT_EQ(expected, result);
}

TEST_F(ConversionsTests, test_json_merge_object) {
  auto doc1 = JSON::newObject();

  size_t value = 10_sz;
  doc1.add("key", value);
  std::string value2 = "value";
  doc1.addRef("key2", value2);

  {
    std::string temp_value = "temp_value";
    doc1.addCopy("temp_key", temp_value);

    auto arr = doc1.getArray();
    doc1.add("array", arr);
  }

  auto doc2 = JSON::newObject();
  doc2.add("new_key", 10_sz);
  doc2.addCopy("new_key1", "new_value");

  doc2.mergeObject(doc2.doc(), doc1.doc());

  std::string result;
  EXPECT_TRUE(doc2.toString(result));

  std::string expected =
      "{\"new_key\":10,\"new_key1\":\"new_value\",\"key\":10,\"key2\":"
      "\"value\",\"temp_key\":\"temp_value\",\"array\":[]}";
  EXPECT_EQ(expected, result);
}

TEST_F(ConversionsTests, test_json_size_like) {
  auto doc = JSON::newObject();
  doc.addRef("key", "10");

  int value = 10;
  doc.add("key2", value);

  EXPECT_EQ(JSON::valueToSize(doc.doc()["key"]), 10_sz);
  EXPECT_EQ(JSON::valueToSize(doc.doc()["key2"]), 10_sz);
}

TEST_F(ConversionsTests, test_json_bool_like) {
  auto doc = JSON::newObject();
  doc.addRef("true1", "true");
  doc.addRef("true2", "T");
  doc.addRef("true3", "t");
  doc.addRef("true4", "TRUE");
  doc.add("true5", 1);

  EXPECT_TRUE(JSON::valueToBool(doc.doc()["true1"]));
  EXPECT_TRUE(JSON::valueToBool(doc.doc()["true2"]));
  EXPECT_TRUE(JSON::valueToBool(doc.doc()["true3"]));
  EXPECT_TRUE(JSON::valueToBool(doc.doc()["true4"]));
  EXPECT_TRUE(JSON::valueToBool(doc.doc()["true5"]));

  doc.addRef("false1", "awesome");
  doc.addRef("false2", "false");
  doc.addRef("false3", "F");
  doc.addRef("false4", "FALSE");
  doc.addRef("false5", "f");
  doc.add("false6", 0);

  EXPECT_FALSE(JSON::valueToBool(doc.doc()["false1"]));
  EXPECT_FALSE(JSON::valueToBool(doc.doc()["false2"]));
  EXPECT_FALSE(JSON::valueToBool(doc.doc()["false3"]));
  EXPECT_FALSE(JSON::valueToBool(doc.doc()["false4"]));
  EXPECT_FALSE(JSON::valueToBool(doc.doc()["false5"]));
  EXPECT_FALSE(JSON::valueToBool(doc.doc()["false6"]));
}

TEST_F(ConversionsTests, tryTo_same_type) {
  class First {};
  // rvalue
  auto ret0 = tryTo<First>(First{});
  ASSERT_FALSE(ret0.isError());

  auto test_lvalue = First{};
  auto ret1 = tryTo<First>(test_lvalue);
  ASSERT_FALSE(ret1.isError());

  const auto const_test_lvalue = First{};
  auto ret2 = tryTo<First>(const_test_lvalue);
  ASSERT_FALSE(ret2.isError());
}

template <typename ValueType, typename StrType>
void testTryToForRvalue(ValueType value, const StrType& str) {
  auto ret = tryTo<ValueType>(StrType{str});
  ASSERT_FALSE(ret.isError());
  ASSERT_EQ(ret.get(), value);
}

template <typename ValueType, typename StrType>
void testTryToForLValue(ValueType value, StrType str) {
  auto ret = tryTo<ValueType>(str);
  ASSERT_FALSE(ret.isError());
  ASSERT_EQ(ret.get(), value);
}

template <typename ValueType, typename StrType>
void testTryToForConstLValue(ValueType value, const StrType str) {
  auto ret = tryTo<ValueType>(str);
  ASSERT_FALSE(ret.isError());
  ASSERT_EQ(ret.get(), value);
}

template <typename ValueType, typename StrType>
void testTryToForString(ValueType value, const StrType str) {
  testTryToForRvalue(value, str);
  testTryToForLValue(value, str);
  testTryToForConstLValue(value, str);
}

template <typename ValueType>
void testTryToForValue(ValueType value) {
  testTryToForString(value, std::to_string(value));
  testTryToForString(value, std::to_wstring(value));
}

template <typename IntType>
void testTryToForInt() {
  testTryToForValue<IntType>(119);
  testTryToForValue<IntType>(std::numeric_limits<IntType>::max());
  testTryToForValue<IntType>(std::numeric_limits<IntType>::min());
  testTryToForValue<IntType>(std::numeric_limits<IntType>::lowest());
  {
    auto ret = tryTo<IntType>(std::string{"0xfb"}, 16);
    ASSERT_FALSE(ret.isError());
    ASSERT_EQ(ret.get(), 251);
  }
  {
    auto ret = tryTo<IntType>(std::string{"FB"}, 16);
    ASSERT_FALSE(ret.isError());
    ASSERT_EQ(ret.get(), 251);
  }
  {
    auto ret = tryTo<IntType>(std::string{"0xFb"}, 16);
    ASSERT_FALSE(ret.isError());
    ASSERT_EQ(ret.get(), 251);
  }
  {
    auto ret = tryTo<IntType>(std::string{"E1bC2"}, 16);
    ASSERT_FALSE(ret.isError());
    ASSERT_EQ(ret.get(), 924610);
  }
  {
    auto ret = tryTo<IntType>(std::string{"10101"}, 2);
    ASSERT_FALSE(ret.isError());
    ASSERT_EQ(ret.get(), 21);
  }
  {
    auto ret = tryTo<IntType>(std::string{"035"}, 8);
    ASSERT_FALSE(ret.isError());
    ASSERT_EQ(ret.get(), 29);
  }
  {
    auto ret = tryTo<IntType>(std::string{"47"}, 8);
    ASSERT_FALSE(ret.isError());
    ASSERT_EQ(ret.get(), 39);
  }
}

TEST_F(ConversionsTests, try_i_to_string_and_back) {
  testTryToForInt<int>();
  testTryToForValue<int>(-126);
}

TEST_F(ConversionsTests, try_l_to_string_and_back) {
  testTryToForInt<long>();
  testTryToForValue<long>(-126);
}

TEST_F(ConversionsTests, try_ll_to_string_and_back) {
  testTryToForInt<long long>();
  testTryToForValue<long long>(-126);
}

TEST_F(ConversionsTests, try_i32_to_string_and_back) {
  testTryToForInt<std::int32_t>();
}

TEST_F(ConversionsTests, try_i64_to_string_and_back) {
  testTryToForInt<std::int64_t>();
}

TEST_F(ConversionsTests, try_imax_to_string_and_back) {
  testTryToForInt<std::intmax_t>();
}

TEST_F(ConversionsTests, try_u_to_string_and_back) {
  testTryToForInt<unsigned>();
}

TEST_F(ConversionsTests, try_ul_to_string_and_back) {
  testTryToForInt<unsigned long>();
}

TEST_F(ConversionsTests, try_ull_to_string_and_back) {
  testTryToForInt<unsigned long long>();
}

TEST_F(ConversionsTests, try_u32_to_string_and_back) {
  testTryToForInt<std::uint32_t>();
}

TEST_F(ConversionsTests, try_u64_to_string_and_back) {
  testTryToForInt<std::uint64_t>();
}

TEST_F(ConversionsTests, try_umax_to_string_and_back) {
  testTryToForInt<std::uintmax_t>();
}

} // namespace osquery
