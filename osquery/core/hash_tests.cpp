/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/hash.h>

#include "osquery/core/test_util.h"

namespace osquery {

class HashTests : public testing::Test {};

TEST_F(HashTests, test_algorithms) {
  const unsigned char buffer[1] = {'0'};

  auto digest = hashFromBuffer(HASH_TYPE_MD5, buffer, 1);
  EXPECT_EQ(digest, "cfcd208495d565ef66e7dff9f98764da");

  digest = hashFromBuffer(HASH_TYPE_SHA1, buffer, 1);
  EXPECT_EQ(digest, "b6589fc6ab0dc82cf12099d1c2d40ab994e8410c");

  digest = hashFromBuffer(HASH_TYPE_SHA256, buffer, 1);
  EXPECT_EQ(digest,
            "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9");
}

TEST_F(HashTests, test_update) {
  const unsigned char buffer[1] = {'0'};

  Hash hash(HASH_TYPE_MD5);
  hash.update(buffer, 1);
  hash.update(buffer, 1);
  auto digest = hash.digest();
  EXPECT_EQ(digest, "b4b147bc522828731f1a016bfa72c073");
}

TEST_F(HashTests, test_file_hashing) {
  auto digest = hashFromFile(HASH_TYPE_MD5, kTestDataPath + "test_hashing.bin");
  EXPECT_EQ(digest, "88ee11f2aa7903f34b8b8785d92208b1");
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  osquery::initOsquery(argc, argv);
  return RUN_ALL_TESTS();
}
