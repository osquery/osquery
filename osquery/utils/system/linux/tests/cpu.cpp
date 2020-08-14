/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <gtest/gtest.h>

#include <osquery/utils/system/linux/cpu.h>

namespace osquery {
namespace {

class SystemCpuTests : public testing::Test {};

TEST_F(SystemCpuTests, decodeMaskFromString_empty_string) {
  auto exp = cpu::decodeMaskFromString("");
  ASSERT_TRUE(exp.isValue());
  ASSERT_EQ(exp.get(), cpu::Mask(0));
}

TEST_F(SystemCpuTests, decodeMaskFromString_0) {
  auto exp = cpu::decodeMaskFromString("0");
  ASSERT_TRUE(exp.isValue());
  ASSERT_EQ(exp.get(), cpu::Mask(1));
}

TEST_F(SystemCpuTests, decodeMaskFromString_7) {
  auto exp = cpu::decodeMaskFromString("7");
  ASSERT_TRUE(exp.isValue());
  ASSERT_EQ(exp.get(), cpu::Mask("10000000"));
}

TEST_F(SystemCpuTests, decodeMaskFromString_from_2_to_4) {
  auto exp = cpu::decodeMaskFromString("2-4");
  ASSERT_TRUE(exp.isValue());
  ASSERT_EQ(exp.get(), cpu::Mask("11100"));
}

TEST_F(SystemCpuTests, decodeMaskFromString_0_from_2_to_5) {
  auto exp = cpu::decodeMaskFromString("0,2-5");
  ASSERT_TRUE(exp.isValue());
  ASSERT_EQ(exp.get(), cpu::Mask("111101"));
}

TEST_F(SystemCpuTests, decodeMaskFromString_from_1_to_3_from_6_to_7) {
  auto exp = cpu::decodeMaskFromString("1-3,6-7");
  ASSERT_TRUE(exp.isValue());
  ASSERT_EQ(exp.get(), cpu::Mask("11001110"));
}

TEST_F(SystemCpuTests, decodeMaskFromString_from_1_to_3_from_5_to_7_and_11) {
  auto exp = cpu::decodeMaskFromString("1-3,5-7,11");
  ASSERT_TRUE(exp.isValue());
  ASSERT_EQ(exp.get(), cpu::Mask("100011101110"));
}

TEST_F(SystemCpuTests, decodeMaskFromString_fail_0) {
  auto exp = cpu::decodeMaskFromString("1-0");
  ASSERT_TRUE(exp.isError());
  ASSERT_EQ(exp.getErrorCode(), cpu::Error::IncorrectRange);
}

TEST_F(SystemCpuTests, decodeMaskFromString_fail_1) {
  auto exp = cpu::decodeMaskFromString("1-");
  ASSERT_TRUE(exp.isError());
  ASSERT_EQ(exp.getErrorCode(), cpu::Error::IncorrectRange);
}

TEST_F(SystemCpuTests, decodeMaskFromString_fail_2) {
  auto exp = cpu::decodeMaskFromString("1,-2");
  ASSERT_TRUE(exp.isError());
  ASSERT_EQ(exp.getErrorCode(), cpu::Error::IncorrectRange);
}

TEST_F(SystemCpuTests, decodeMaskFromString_fail_3) {
  auto exp = cpu::decodeMaskFromString(",2");
  ASSERT_TRUE(exp.isError());
  ASSERT_EQ(exp.getErrorCode(), cpu::Error::IncorrectRange);
}

TEST_F(SystemCpuTests, decodeMaskFromString_fail_4) {
  auto exp = cpu::decodeMaskFromString("0,9-a");
  ASSERT_TRUE(exp.isError());
  ASSERT_EQ(exp.getErrorCode(), cpu::Error::IncorrectRange);
}

TEST_F(SystemCpuTests, decodeMaskFromString_fail_5) {
  auto exp = cpu::decodeMaskFromString("b");
  ASSERT_TRUE(exp.isError());
  ASSERT_EQ(exp.getErrorCode(), cpu::Error::IncorrectRange);
}

TEST_F(SystemCpuTests, getOfflineRaw) {
  auto exp = cpu::getOfflineRaw();
  ASSERT_TRUE(exp.isValue());
  ASSERT_TRUE(cpu::decodeMaskFromString(exp.get()));
}

TEST_F(SystemCpuTests, getOffline) {
  auto exp = cpu::getOffline();
  ASSERT_TRUE(exp.isValue());
}

TEST_F(SystemCpuTests, getOnlineRaw) {
  auto exp = cpu::getOnlineRaw();
  ASSERT_TRUE(exp.isValue());
  ASSERT_TRUE(cpu::decodeMaskFromString(exp.get()));
}

TEST_F(SystemCpuTests, getOnline) {
  auto exp = cpu::getOnline();
  ASSERT_TRUE(exp.isValue());
}

TEST_F(SystemCpuTests, getPossibleRaw) {
  auto exp = cpu::getPossibleRaw();
  ASSERT_TRUE(exp.isValue());
  ASSERT_TRUE(cpu::decodeMaskFromString(exp.get()));
}

TEST_F(SystemCpuTests, getPossible) {
  auto exp = cpu::getPossible();
  ASSERT_TRUE(exp.isValue());
}

TEST_F(SystemCpuTests, getPresentRaw) {
  auto exp = cpu::getPresentRaw();
  ASSERT_TRUE(exp.isValue());
  ASSERT_TRUE(cpu::decodeMaskFromString(exp.get()));
}

TEST_F(SystemCpuTests, getPresent) {
  auto exp = cpu::getPresent();
  ASSERT_TRUE(exp.isValue());
}

} // namespace
} // namespace osquery
