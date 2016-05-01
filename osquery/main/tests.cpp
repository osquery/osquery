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

#include <osquery/logger.h>

#include "osquery/core/process.h"
#include "osquery/core/test_util.h"

// TODO(#1991): We import and export the following symbols to support launchWorker
//              and launchExtension unit tests. The question for the future is how
//              to integrate it better so that the main tests.cpp doesn't have 
//              dependencies on unit tests elsewhere.
char *self_exec_path = nullptr;
extern int workerMain(int argc, char *argv[]);
extern int extensionMain(int argc, char *argv[]);

int main(int argc, char* argv[]) {
  if (auto val = osquery::getEnvVar("OSQUERY_WORKER")) {
    return workerMain(argc, argv);
  } else if (val = osquery::getEnvVar("OSQUERY_EXTENSIONS")) {
    return extensionMain(argc, argv);
  }
  self_exec_path = argv[0];

  osquery::initTesting();
  testing::InitGoogleTest(&argc, argv);
  // Optionally enable Goggle Logging
  // google::InitGoogleLogging(argv[0]);
  auto result = RUN_ALL_TESTS();

  osquery::shutdownTesting();
  return result;
}
