/*
 *  Copyright (c) 2015, Wesley Shields
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <cstdlib>

#include <time.h>

#include <gtest/gtest.h>

int main(int argc, char* argv[]) {
  srand(time(nullptr));
  testing::InitGoogleTest(&argc, argv);
  // Optionally enable Goggle Logging
  // google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
