/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/core.h>
#include <osquery/core/system.h>

#include <shlobj.h>

#include "osquery/core/windows/comptr.h"

namespace osquery {

class ComPtrTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
  }
};

TEST_F(ComPtrTests, test_basic_comptr) {
  ComPtr<IUnknown> unk;
  EXPECT_TRUE(SUCCEEDED(unk.createInstance(CLSID_ShellLink)));
  ComPtr<IUnknown> unk2;
  unk2.attach(unk.detach());
  EXPECT_TRUE(unk == nullptr);
  EXPECT_TRUE(unk2 != nullptr);

  ComPtr<IMalloc> mem_alloc;
  EXPECT_TRUE(SUCCEEDED(CoGetMalloc(1, mem_alloc.receive())));

  ComPtr<IUnknown> qi_test;
  EXPECT_HRESULT_SUCCEEDED(
      mem_alloc.queryInterface(IID_IUnknown, qi_test.receiveVoid()));
  EXPECT_TRUE(qi_test.get() != nullptr);
  qi_test.release();

  // test ComPtr& constructor
  ComPtr<IMalloc> copy1(mem_alloc);
  IMalloc* naked_copy = copy1.detach();
  copy1 = naked_copy; // Test the =(T*) operator.
  naked_copy->Release();

  copy1.release();
}

} // namespace osquery
