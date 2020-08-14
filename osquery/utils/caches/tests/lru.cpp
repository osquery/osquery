/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/utils/caches/lru.h>

namespace osquery {
namespace {

class LruCacheTests : public testing::Test {};

TEST_F(LruCacheTests, size) {
  auto cache = caches::LRU<int, int>(7);
  EXPECT_EQ(cache.size(), 0u);
  cache.insert(1, 20);
  cache.insert(2, 21);
  EXPECT_EQ(cache.size(), 2u);
}

TEST_F(LruCacheTests, capacity) {
  auto cache = caches::LRU<int, int>(7);
  EXPECT_EQ(cache.capacity(), 7u);
  cache.insert(1, 20);
  cache.insert(2, 21);
  EXPECT_EQ(cache.capacity(), 7u);
}

TEST_F(LruCacheTests, get_non_existing) {
  auto cache = caches::LRU<int, int>(8);
  cache.insert(1, 20);
  cache.insert(2, 21);
  cache.insert(3, 22);
  auto v_ptr = cache.get(13);
  EXPECT_EQ(v_ptr, nullptr);
}

TEST_F(LruCacheTests, get_existing) {
  auto cache = caches::LRU<int, int>(8);
  cache.insert(1, 20);
  cache.insert(2, 21);
  cache.insert(3, 22);
  auto v_ptr = cache.get(2);
  EXPECT_NE(v_ptr, nullptr);
  EXPECT_EQ(*v_ptr, 21);
}

TEST_F(LruCacheTests, displace) {
  auto cache = caches::LRU<int, int>(4);
  cache.insert(1, 21);
  {
    auto v_ptr = cache.get(1);
    EXPECT_NE(v_ptr, nullptr);
    EXPECT_EQ(*v_ptr, 21);
  }
  cache.insert(2, 22);
  cache.insert(3, 23);
  cache.insert(4, 24);
  {
    // still here
    auto v_ptr = cache.get(1);
    EXPECT_NE(v_ptr, nullptr);
    EXPECT_EQ(*v_ptr, 21);
  }
  cache.insert(2, 22);
  cache.insert(3, 23);
  cache.insert(4, 24);
  cache.insert(5, 25);
  {
    // still here
    auto v_ptr = cache.get(1);
    EXPECT_EQ(v_ptr, nullptr);
  }
}

TEST_F(LruCacheTests, reinsert) {
  auto cache = caches::LRU<int, int>(8);
  cache.insert(19, 212);
  {
    auto v_ptr = cache.get(19);
    EXPECT_NE(v_ptr, nullptr);
    EXPECT_EQ(*v_ptr, 212);
  }
  cache.insert(19, 308);
  {
    auto v_ptr = cache.get(19);
    EXPECT_NE(v_ptr, nullptr);
    EXPECT_EQ(*v_ptr, 308);
  }
}

TEST_F(LruCacheTests, has) {
  auto cache = caches::LRU<int, int>(2);
  cache.insert(19, 212);
  cache.insert(18, 212);
  EXPECT_TRUE(cache.has(19));
  EXPECT_TRUE(cache.has(18));
  EXPECT_FALSE(cache.has(-18));
}

TEST_F(LruCacheTests, has_does_not_change_the_place_in_queue) {
  auto cache = caches::LRU<int, int>(2);
  cache.insert(1, 212);
  cache.insert(2, 212);
  EXPECT_TRUE(cache.has(1));
  cache.insert(3, 212);
  EXPECT_FALSE(cache.has(1));
  EXPECT_TRUE(cache.has(2));
  EXPECT_TRUE(cache.has(3));
}

TEST_F(LruCacheTests, pointer_validity_after_insertions) {
  auto cache = caches::LRU<int, std::string>(16);
  auto ptr_1 = cache.insert(1, "Arctic");
  EXPECT_NE(ptr_1, nullptr);

  cache.insert(2, "Atlantic");
  auto ptr_2 = cache.get(2);
  EXPECT_NE(ptr_2, nullptr);

  cache.insert(3, "Indian");
  cache.insert(4, "Pacific");
  cache.insert(5, "Southern");

  EXPECT_EQ(*ptr_1, "Arctic");
  EXPECT_EQ(*ptr_2, "Atlantic");
}

} // namespace
} // namespace osquery
