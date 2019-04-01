/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/schemer/json/schemer_json.h>

#include <osquery/utils/conversions/to.h>

#include <gtest/gtest.h>

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

 private:
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

} // namespace
} // namespace osquery
