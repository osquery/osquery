/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/core.h>
#include <osquery/core/system.h>

#include <shlobj.h>

#include "osquery/core/windows/comptr.h"

namespace osquery {

namespace {

// Mock object that can count AddRef and Release calls.
// Will *not* delete the object if reference count is 0.
struct MockCOMObject {
  MockCOMObject() : adds(0), releases(0) {}
  void AddRef() {
    ++adds;
  }
  void Release() {
    ++releases;
  }

  int adds;
  int releases;
};

extern const IID mockObjectIID;
const IID mockObjectIID = {
    0x12345678u, 0x1234u, 0x5678u, 01, 23, 45, 67, 89, 01, 23, 45};

} // namespace

class ComPtrTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
  }
};

TEST_F(ComPtrTests, test_basic_comptr) {
  ComPtr<IUnknown> unk;
  EXPECT_HRESULT_SUCCEEDED(unk.createInstance(CLSID_ShellLink));
  ComPtr<IUnknown> unk2;
  unk2.attach(unk.detach());
  EXPECT_TRUE(!unk);
  EXPECT_TRUE(unk2);

  ComPtr<IMalloc> mem_alloc;
  EXPECT_HRESULT_SUCCEEDED(CoGetMalloc(1, mem_alloc.receive()));

  ComPtr<IUnknown> qi_test;
  EXPECT_HRESULT_SUCCEEDED(
      mem_alloc.queryInterface(IID_IUnknown, qi_test.receiveVoid()));
  EXPECT_TRUE(qi_test.get() != nullptr);
  qi_test.release();

  // Test ComPtr& constructor.
  ComPtr<IMalloc> copy1(mem_alloc);
  IMalloc* naked_copy = copy1.detach();

  // Test the =(T*) operator.
  copy1 = naked_copy;
  naked_copy->Release();
  copy1.release();

  // Test =(ComPtr&) operator.
  copy1 = mem_alloc;
  // Compare pointer but not the reference counter.
  EXPECT_EQ(copy1, mem_alloc);
}

TEST_F(ComPtrTests, test_mock_counters) {
  MockCOMObject mockObj;
  // Initial state.
  EXPECT_EQ(0, mockObj.adds);
  EXPECT_EQ(0, mockObj.releases);

  // Make a ComPtr that will guard our mock object.
  ComPtr<MockCOMObject, &mockObjectIID> mockPtr(&mockObj);

  EXPECT_EQ(1, mockObj.adds);
  EXPECT_EQ(0, mockObj.releases);

  {
    // Make a copy of the first guard.
    ComPtr<MockCOMObject, &mockObjectIID> mockPtr2(mockPtr);

    // Should add more refs.
    EXPECT_EQ(2, mockObj.adds);
    EXPECT_EQ(0, mockObj.releases);
  }

  EXPECT_EQ(1, mockObj.releases);

  // New object.
  MockCOMObject mockObj2;

  mockPtr = &mockObj2;

  // First object should be released.
  EXPECT_EQ(2, mockObj.adds);
  EXPECT_EQ(2, mockObj.releases);

  // Second object should be referenced.
  EXPECT_EQ(1, mockObj2.adds);
  EXPECT_EQ(0, mockObj2.releases);

  mockPtr.release();
  // Second object should be released.
  EXPECT_EQ(1, mockObj2.adds);
  EXPECT_EQ(1, mockObj2.releases);
}

} // namespace osquery
