/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/system.h>

#include <oleauto.h>

#include "osquery/core/windows/bstr.h"

namespace osquery {

TEST(BstrTests, test_copy) {
  Bstr bstr;

  {
    Bstr inner(SysAllocString(L"hello"));
    bstr = std::move(inner);
  }

  EXPECT_EQ(0, wcscmp(bstr.get(), L"hello"));
  EXPECT_EQ(4, bstr.length());
  EXPECT_EQ(8, bstr.byteLength());
  // here `bstr` object should be deleted.
}

TEST(BstrTests, test_reset) {
  Bstr bstr(SysAllocString(L"hello"));
  EXPECT_TRUE(static_cast<bool>(bstr));

  bstr.reset();

  EXPECT_EQ(nullptr, bstr.get());
  EXPECT_FALSE(static_cast<bool>(bstr));
}

TEST(BstrTests, test_release) {
  Bstr bstr(SysAllocString(L"hello"));
  auto raw_bstr = bstr.release();

  EXPECT_EQ(nullptr, bstr.get());

  *bstr.receiveAddress() = raw_bstr;
  EXPECT_EQ(0, wcscmp(bstr.get(), L"hello"));
}

TEST(BstrTests, test_from_string) {
  Bstr bstr = Bstr::fromString(std::wstring(L"hello"));
  EXPECT_TRUE(static_cast<bool>(bstr));
  EXPECT_EQ(0, wcscmp(bstr.get(), L"hello"));
  EXPECT_EQ(4, bstr.length());
}

} // namespace osquery
