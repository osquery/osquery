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

#include <osquery/utils/conversions/tryto.h>

namespace osquery {

class ConversionsTests : public testing::Test {};


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
void testTryToForUnsignedInt() {
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
  {
    auto ret = tryTo<IntType>(std::string{"+15"});
    ASSERT_FALSE(ret.isError());
    ASSERT_EQ(ret.get(), 15);
  }
  {
    auto ret = tryTo<IntType>(std::string{"+1A"}, 16);
    ASSERT_FALSE(ret.isError());
    ASSERT_EQ(ret.get(), 26);
  }
  // failure tests
  {
    auto ret = tryTo<IntType>(std::string{""});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"x"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"xor"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{".1"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"(10)"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"O"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"lO0"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"IV"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"s1"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"u1"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"#12"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"%99"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"*483"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"/488"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"\\493"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"+ 19"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string(2, '\0'));
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
}

template <typename IntType>
void testTryToForSignedInt() {
  testTryToForUnsignedInt<IntType>();
  testTryToForValue<int>(-126);
  {
    auto ret = tryTo<IntType>(std::string{"-7A"}, 16);
    ASSERT_FALSE(ret.isError());
    ASSERT_EQ(ret.get(), -122);
  }
  // failure tests
  {
    auto ret = tryTo<IntType>(std::string{"--14779"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"+-1813"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
  {
    auto ret = tryTo<IntType>(std::string{"- 3"});
    ASSERT_TRUE(ret.isError());
    ASSERT_EQ(ret.getErrorCode(), ConversionError::InvalidArgument);
  }
}

TEST_F(ConversionsTests, try_i_to_string_and_back) {
  testTryToForSignedInt<int>();
}

TEST_F(ConversionsTests, try_l_to_string_and_back) {
  testTryToForSignedInt<long>();
}

TEST_F(ConversionsTests, try_ll_to_string_and_back) {
  testTryToForSignedInt<long long>();
}

TEST_F(ConversionsTests, try_i32_to_string_and_back) {
  testTryToForSignedInt<std::int32_t>();
}

TEST_F(ConversionsTests, try_i64_to_string_and_back) {
  testTryToForSignedInt<std::int64_t>();
}

TEST_F(ConversionsTests, try_imax_to_string_and_back) {
  testTryToForSignedInt<std::intmax_t>();
}

TEST_F(ConversionsTests, try_u_to_string_and_back) {
  testTryToForUnsignedInt<unsigned>();
}

TEST_F(ConversionsTests, try_ul_to_string_and_back) {
  testTryToForUnsignedInt<unsigned long>();
}

TEST_F(ConversionsTests, try_ull_to_string_and_back) {
  testTryToForUnsignedInt<unsigned long long>();
}

TEST_F(ConversionsTests, try_u32_to_string_and_back) {
  testTryToForUnsignedInt<std::uint32_t>();
}

TEST_F(ConversionsTests, try_u64_to_string_and_back) {
  testTryToForUnsignedInt<std::uint64_t>();
}

TEST_F(ConversionsTests, try_umax_to_string_and_back) {
  testTryToForUnsignedInt<std::uintmax_t>();
}

TEST_F(ConversionsTests, try_size_t_to_string_and_back) {
  testTryToForUnsignedInt<std::size_t>();
}

TEST_F(ConversionsTests, tryTo_string_to_boolean_valid_args) {
  const auto test_table = std::unordered_map<std::string, bool>{
      {"1", true},        {"0", false},       {"y", true},
      {"n", false},       {"yes", true},      {"yEs", true},
      {"Yes", true},      {"no", false},      {"No", false},
      {"t", true},        {"T", true},        {"f", false},
      {"F", false},       {"true", true},     {"True", true},
      {"tRUE", true},     {"false", false},   {"fALse", false},
      {"ok", true},       {"OK", true},       {"Ok", true},
      {"enable", true},   {"Enable", true},   {"ENABLE", true},
      {"disable", false}, {"Disable", false}, {"DISABLE", false},
  };
  for (const auto& argAndAnswer : test_table) {
    auto exp = tryTo<bool>(argAndAnswer.first);
    ASSERT_FALSE(exp.isError());
    EXPECT_EQ(argAndAnswer.second, exp.get());
  }
}

TEST_F(ConversionsTests, tryTo_string_to_boolean_invalid_args) {
  const auto test_table = std::vector<std::string>{
      "",       "\0",      "\n",      "\x06",  "\x15",   "\x27",     "ADS",
      "7251",   "20.09",   "M0V+K7V", "+",     "-",      ".",        "@",
      "1.0",    "11",      "00",      " 0",    "1 ",     "2",        "10",
      "100%",   "_0",      "1_",      "1.",    "2.",     "E",        "a",
      "b",      "d",       "e",       "o",     "p",      "uh",       "nix",
      "nixie",  "nixy",    "nixey",   "nay",   "nah",    "no way",   "veto",
      "yea",    "yeah",    "yep",     "okey",  "aye",    "roger",    "uh-huh",
      "righto", "yup",     "yuppers", "ja",    "surely", "amen",     "totally",
      "sure",   "yessir",  "true.",   "tru",   "tr",     "tr.",      "ff",
      "yy",     "nn",      "nope",    "null",  "nil",    "dis",      "able",
      "pos",    "neg",     "ack",     "ACK",   "NAK",    "enabled",  "disabled",
      "valid",  "invalid", "void",    "allow", "permit", "positive", "negative",
  };
  for (const auto& wrong : test_table) {
    auto exp = tryTo<bool>(wrong);
    ASSERT_TRUE(exp.isError());
    EXPECT_EQ(ConversionError::InvalidArgument, exp.getErrorCode());
  }
}

} // namespace osquery
