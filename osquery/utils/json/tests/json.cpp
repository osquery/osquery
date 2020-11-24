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

#include <osquery/utils/json/json.h>

namespace osquery {

class ConversionsTests : public testing::Test {};

TEST_F(ConversionsTests, test_json_array) {
  auto doc = JSON::newArray();

  {
    auto obj = doc.getObject();
    size_t value = 10;
    doc.add("key", value, obj);
    int value2 = -10;
    doc.add("key2", value2, obj);
    int64_t value3 = (uint64_t(1)) << 48;
    doc.add("key3", value3, obj);
    double value4 = 3.14159265359;
    doc.add("key4", value4, obj);
    doc.push(obj);
  }

  size_t value = 11;
  doc.push(value);

  std::string result;
  EXPECT_TRUE(doc.toString(result));

  std::string expected =
      "[{\"key\":10,\"key2\":-10,\"key3\":281474976710656,\"key4\":3."
      "14159265359},11]";
  EXPECT_EQ(expected, result);

  EXPECT_TRUE(doc.toPrettyString(result));

  std::string expectedPretty =
      "[\n  {\n    \"key\": 10,\n    \"key2\": -10,\n    \"key3\": "
      "281474976710656,\n    \"key4\": 3.14159265359\n  },\n  11\n]";
  EXPECT_EQ(expectedPretty, result);

  EXPECT_TRUE(doc.toPrettyString(result, 1 /*indentCharCount*/));

  std::string expectedPrettyNonDefaultIndent =
      "[\n {\n  \"key\": 10,\n  \"key2\": -10,\n  \"key3\": "
      "281474976710656,\n  \"key4\": 3.14159265359\n },\n 11\n]";
  EXPECT_EQ(expectedPrettyNonDefaultIndent, result);
}

TEST_F(ConversionsTests, test_json_object) {
  auto doc = JSON::newObject();

  {
    size_t value = 10;
    doc.add("key", value);
  }

  std::string result;
  EXPECT_TRUE(doc.toString(result));

  std::string expected = "{\"key\":10}";
  EXPECT_EQ(expected, result);

  EXPECT_TRUE(doc.toPrettyString(result));

  std::string expectedPretty = "{\n  \"key\": 10\n}";
  EXPECT_EQ(expectedPretty, result);

  EXPECT_TRUE(doc.toPrettyString(result, 3 /*indentCharCount*/));

  std::string expectedPrettyNonDefaultIndent = "{\n   \"key\": 10\n}";
  EXPECT_EQ(expectedPrettyNonDefaultIndent, result);
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

  size_t value = 10;
  doc.add("key", value);
  value = 11;
  doc.add("key", value);

  std::string result;
  EXPECT_TRUE(doc.toString(result));

  std::string expected = "{\"key\":11}";
  EXPECT_EQ(expected, result);
}

TEST_F(ConversionsTests, test_json_merge_object) {
  auto doc1 = JSON::newObject();

  size_t value = 10;
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
  doc2.add("new_key", size_t{10});
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

  EXPECT_EQ(JSON::valueToSize(doc.doc()["key"]), size_t{10});
  EXPECT_EQ(JSON::valueToSize(doc.doc()["key2"]), size_t{10});
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

/*
 * By default, rapidjson will use recursive parsing without stack guards,
 * which would result in a segfault for this test. To guard against
 * malicious json, we should be configured to use iterative mode.
 * https://github.com/Tencent/rapidjson/issues/632
 */
TEST_F(ConversionsTests, test_json_iterativeparsing) {
  std::string json(543210, '[');
  auto doc = JSON::newObject();

  EXPECT_FALSE(doc.fromString(json).ok());
}

TEST_F(ConversionsTests, test_json_largeexp) {
  std::string json("0.0000074836628E-2147483636");
  auto doc = JSON::newObject();

  EXPECT_TRUE(doc.fromString(json).ok());
}
} // namespace osquery
