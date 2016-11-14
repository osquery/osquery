/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/sha1.h>

namespace osquery {

class SHA1tests : public testing::Test {};

TEST_F(SHA1tests, test_buffer_sha1) {
  std::string test = "test\n";
  EXPECT_EQ("4e1243bd22c66e76c2ba9eddc1f91394e57f9f83",
            getBufferSHA1(test.c_str(), test.size()));
}
}
