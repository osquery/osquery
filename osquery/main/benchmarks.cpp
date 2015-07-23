/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <benchmark/benchmark.h>

#include "osquery/core/test_util.h"

int main(int argc, const char* argv[]) {
  osquery::initTesting();
  ::benchmark::Initialize(&argc, argv);
  ::benchmark::RunSpecifiedBenchmarks();
  // Optionally enable Goggle Logging
  // google::InitGoogleLogging(argv[0]);
  return 0;
}
