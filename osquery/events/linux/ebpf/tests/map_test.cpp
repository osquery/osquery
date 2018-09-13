/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/events/linux/ebpf/ebpf.h"

#include <osquery/tests/test_util.h>

#include <gtest/gtest.h>

namespace osquery {
namespace {

class EbpfMapTests : public testing::Test {};

TEST_F(EbpfMapTests, key_int_value_int) {
  auto const size = std::size_t{12};
  auto map_exp = ebpf::createMap<int, int, BPF_MAP_TYPE_HASH>(size);
  ASSERT_TRUE(map_exp.isValue())
      << map_exp.getError().getFullMessageRecursive();
  auto map = map_exp.take();
  ASSERT_EQ(map.size(), size);
  {
    auto exp = map.lookupElement(0);
    ASSERT_TRUE(exp.isError());
    EXPECT_EQ(exp.getError().getErrorCode(), ebpf::MapError::NoSuchKey);
  }
  {
    auto exp = map.lookupElement(215);
    ASSERT_TRUE(exp.isError());
    EXPECT_EQ(exp.getError().getErrorCode(), ebpf::MapError::NoSuchKey);
  }
  {
    auto exp = map.updateElement(5, 53);
    ASSERT_TRUE(exp.isValue()) << exp.getError().getFullMessageRecursive();
  }
  {
    auto exp = map.lookupElement(5);
    ASSERT_TRUE(exp.isValue()) << exp.getError().getFullMessageRecursive();
    ASSERT_EQ(exp.get(), 53);
  }
  {
    // key could be greater a size, because it is a hash map
    auto exp = map.updateElement(207, 8042);
    ASSERT_TRUE(exp.isValue()) << exp.getError().getFullMessageRecursive();
  }
  {
    auto exp = map.lookupElement(207);
    ASSERT_TRUE(exp.isValue()) << exp.getError().getFullMessageRecursive();
    ASSERT_EQ(exp.get(), 8042);
  }
  {
    // let's try to delete some existing key
    auto exp = map.deleteElement(207);
    ASSERT_TRUE(exp.isValue()) << exp.getError().getFullMessageRecursive();
  }
  {
    auto exp = map.lookupElement(207);
    ASSERT_TRUE(exp.isError());
    EXPECT_EQ(exp.getError().getErrorCode(), ebpf::MapError::NoSuchKey);
  }
}

TEST_F(EbpfMapTests, key_int_value_struct) {
  struct Value {
    int left;
    int right;
  };
  auto const size = std::size_t{128};
  auto map_exp = ebpf::createMap<int, Value, BPF_MAP_TYPE_ARRAY>(size);
  ASSERT_TRUE(map_exp.isValue());
  auto map = map_exp.take();
  ASSERT_EQ(map.size(), size);
  {
    auto const v = Value{
        .left = -9287,
        .right = 2781,
    };
    auto exp = map.updateElement(72, v);
    ASSERT_TRUE(exp.isValue()) << exp.getError().getFullMessageRecursive();
  }
  {
    auto exp = map.lookupElement(72);
    ASSERT_TRUE(exp.isValue()) << exp.getError().getFullMessageRecursive();
    EXPECT_EQ(exp.get().left, -9287);
    EXPECT_EQ(exp.get().right, 2781);
  }
}

} // namespace
} // namespace osquery
