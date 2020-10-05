/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/schemer/json/schemer_json.h>

#include <osquery/utils/conversions/to.h>

#include <gtest/gtest.h>

#include <limits>
#include <string>
#include <vector>

namespace osquery {
namespace {

class SchemerJsonTests : public testing::Test {};

class TestClass {
 public:
  template <typename Archive, typename ValueType>
  static void discloseSchema(Archive& a, ValueType& value) {
    schemer::record(a, "Bravo", value.b_v_);
    schemer::record(a, "India", value.i_v_);
    schemer::record(a, "Uniform", value.ui_v_);
    schemer::record(a, "Sierra", value.str_v_);
  }

 public:
  bool b_v_ = true;
  int i_v_ = -92374;
  int ui_v_ = 64774;
  std::string str_v_ = "What is Architecture?";
};

TEST_F(SchemerJsonTests, writer_to_stream) {
  auto const v = TestClass{};
  auto buf = rapidjson::StringBuffer{};
  auto const retcode = schemer::toJson(buf, v);
  EXPECT_TRUE(retcode) << retcode.getError().getMessage();
  EXPECT_EQ(
      std::string{buf.GetString()},
      R"json({"Bravo":true,"India":-92374,"Uniform":64774,"Sierra":"What is Architecture?"})json");
}

TEST_F(SchemerJsonTests, writer_to_string) {
  auto const v = TestClass{};
  auto const exp = schemer::toJson(v);
  EXPECT_TRUE(exp) << exp.getError().getMessage();
  EXPECT_EQ(
      exp.get(),
      R"json({"Bravo":true,"India":-92374,"Uniform":64774,"Sierra":"What is Architecture?"})json");
}

class NestedTestClass {
 public:
  template <typename Archive, typename ValueType>
  static void discloseSchema(Archive& a, ValueType& value) {
    schemer::record(a, "First", value.first_);
    schemer::record(a, "test_class", value.second_);
  }

 public:
  int first_ = -273;
  TestClass second_;
};

TEST_F(SchemerJsonTests, writer_nested_to_string) {
  auto const v = NestedTestClass{};
  auto const exp = schemer::toJson(v);
  EXPECT_TRUE(exp) << exp.getError().getMessage();
  EXPECT_EQ(
      exp.get(),
      R"json({"First":-273,"test_class":{"Bravo":true,"India":-92374,"Uniform":64774,"Sierra":"What is Architecture?"}})json");
}

class SecondTestClass {
 public:
  template <typename Archive, typename ValueType>
  static void discloseSchema(Archive& a, ValueType& value) {
    schemer::record(a, "first", value.first_);
    schemer::record(a, "second", value.second_);
    schemer::record(a, "third", value.third_);
    schemer::record(a, "fourth", value.fourth_);
  }

  std::string const& getFirst() const {
    return first_;
  }

  int const& getSecond() const {
    return second_;
  }

  double const& getThird() const {
    return third_;
  }

  bool const& getFourth() const {
    return fourth_;
  }

 private:
  std::string first_ = __FILE__;
  int second_ = __LINE__;
  double third_ = -1;
  bool fourth_ = false;
};

TEST_F(SchemerJsonTests, read_from_stream) {
  auto v = SecondTestClass{};
  auto buf = rapidjson::StringStream{
      R"json({
      "first":"main page",
      "second":-22,
      "third":3.14,
      "fourth":true
    })json"};
  auto const retcode = schemer::fromJson(v, buf);
  ASSERT_TRUE(retcode.isValue()) << retcode.getError().getMessage();
  EXPECT_EQ("main page", v.getFirst());
  EXPECT_EQ(-22, v.getSecond());
  EXPECT_NEAR(3.14, v.getThird(), 0.001);
  EXPECT_EQ(true, v.getFourth());
}

TEST_F(SchemerJsonTests, read_from_stream_syntax_error) {
  auto v = SecondTestClass{};
  auto buf = rapidjson::StringStream{R"json({{)json"};
  auto const retcode = schemer::fromJson(v, buf);
  ASSERT_TRUE(retcode.isError());
  ASSERT_EQ(retcode.getErrorCode(), schemer::JsonError::Syntax);
}

TEST_F(SchemerJsonTests, read_from_stream_object_type_error) {
  auto v = SecondTestClass{};
  auto buf = rapidjson::StringStream{
      R"json([
      {
        "first":"main page",
        "second":-22,
        "third":3.14,
        "fourth":true
      }
    ])json"};
  auto const retcode = schemer::fromJson(v, buf);
  ASSERT_TRUE(retcode.isError());
  ASSERT_EQ(retcode.getErrorCode(), schemer::JsonError::IncorrectFormat);
}

TEST_F(SchemerJsonTests, read_from_stream_member_type_error) {
  auto v = SecondTestClass{};
  auto buf = rapidjson::StringStream{
      R"json({
      "first":"main page",
      "second":"here must be number instead of string",
      "third":3.14,
      "fourth":true
    })json"};
  auto const retcode = schemer::fromJson(v, buf);
  ASSERT_TRUE(retcode.isError());
  ASSERT_EQ(retcode.getErrorCode(), schemer::JsonError::IncorrectFormat)
      << retcode.getError().getMessage();
}

TEST_F(SchemerJsonTests, read_from_stream_missed_key) {
  auto v = SecondTestClass{};
  auto buf = rapidjson::StringStream{R"json({"first":"main page"})json"};
  auto const retcode = schemer::fromJson(v, buf);
  ASSERT_TRUE(retcode.isError());
  ASSERT_EQ(retcode.getErrorCode(), schemer::JsonError::IncorrectFormat)
      << retcode.getError().getMessage();
}

struct ThirdTestClass {
 public:
  template <typename Archive, typename ValueType>
  static void discloseSchema(Archive& a, ValueType& value) {
    schemer::record(a, "first", value.first);
    schemer::record(a, "second", value.second);
    schemer::record(a, "third", value.third);
    schemer::record(a, "fourth", value.fourth);
  }

  std::string first = "";
  unsigned second = 0u;
  double third = 0.;
  std::int64_t fourth = 0;
};

TEST_F(SchemerJsonTests, read_write) {
  auto fromValue = ThirdTestClass{};
  fromValue.first = "\a\b\t\n\v\f\r ";
  fromValue.first.push_back('\0');
  fromValue.first += R"ascii(
0@P`p!1AQaq"2BRbr#3CScs$4DTdt%5EUeu&6FVfv'7GWgw
(8HXhx)9IYiy*:JZjz+;K[k{,<L\l|-=M]m}.>N^n~/?O_o
)ascii";
  fromValue.second = std::numeric_limits<unsigned>::max();
  fromValue.third = std::numeric_limits<float>::max();
  fromValue.fourth = std::numeric_limits<std::int64_t>::min();

  auto const exp_str = schemer::toJson(fromValue);
  EXPECT_TRUE(exp_str.isValue()) << exp_str.getError().getMessage();

  auto toValue = ThirdTestClass{};
  auto const retcode = schemer::fromJson(toValue, exp_str.get().c_str());
  ASSERT_TRUE(retcode.isValue()) << retcode.getError().getMessage();

  EXPECT_EQ(fromValue.first, toValue.first);
  EXPECT_EQ(fromValue.second, toValue.second);
  EXPECT_NEAR(fromValue.third, toValue.third, 0.00001);
  EXPECT_EQ(fromValue.fourth, toValue.fourth);
}

TEST_F(SchemerJsonTests, read_nested_from_string) {
  auto const str =
      R"json({"First":-459,"test_class":{"Bravo":false,"India":31,"Uniform":145,"Sierra":"I have no clue"}})json";
  auto value = NestedTestClass{};
  auto const retcode = schemer::fromJson(value, str);
  ASSERT_TRUE(retcode.isValue()) << retcode.getError().getMessage();

  EXPECT_EQ(value.first_, -459);
  EXPECT_EQ(value.second_.b_v_, false);
  EXPECT_EQ(value.second_.i_v_, 31);
  EXPECT_EQ(value.second_.ui_v_, 145);
  EXPECT_EQ(value.second_.str_v_, "I have no clue");
}

TEST_F(SchemerJsonTests,
       read_nested_from_string_fails_because_value_is_not_an_object) {
  auto const str = R"json({"First":-459,"test_class":false})json";
  auto value = NestedTestClass{};
  auto const retcode = schemer::fromJson(value, str);
  ASSERT_TRUE(retcode.isError());
  EXPECT_EQ(retcode.getErrorCode(), schemer::JsonError::IncorrectFormat);
}

TEST_F(SchemerJsonTests,
       read_nested_from_string_fails_because_of_incomplete_json) {
  // here is JSON with missed last '}'
  auto const str = R"json({
      "First":-459,
      "test_class":{
        "Bravo":false,
        "India":31,
        "Uniform":145,
        "Sierra":"I have no clue"
      }
  )json";
  auto value = NestedTestClass{};
  auto const retcode = schemer::fromJson(value, str);
  ASSERT_TRUE(retcode.isError());
  EXPECT_EQ(retcode.getErrorCode(), schemer::JsonError::Syntax);
}

} // namespace
} // namespace osquery
