/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <cstdlib>
#include <chrono>

#include <time.h>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include "osquery/core/test_util.h"
#include "osquery/database/db_handle.h"

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_string(database_path);
DECLARE_string(extensions_socket);
DECLARE_string(modules_autoload);
DECLARE_string(extensions_autoload);
DECLARE_bool(disable_logging);

typedef std::chrono::high_resolution_clock chrono_clock;

void initTesting() {
  // Seed the random number generator, some tests generate temporary files
  // ports, sockets, etc using random numbers.
  std::srand(chrono_clock::now().time_since_epoch().count());

  // Set safe default values for path-based flags.
  // Specific unittests may edit flags temporarily.
  fs::remove_all(kTestWorkingDirectory);
  fs::create_directories(kTestWorkingDirectory);
  FLAGS_database_path = kTestWorkingDirectory + "unittests.db";
  FLAGS_extensions_socket = kTestWorkingDirectory + "unittests.em";
  FLAGS_extensions_autoload = kTestWorkingDirectory + "unittests-ext.load";
  FLAGS_modules_autoload = kTestWorkingDirectory + "unittests-mod.load";
  FLAGS_disable_logging = true;

  // Create a default DBHandle instance before unittests.
  (void)DBHandle::getInstance();
}
}

int main(int argc, char* argv[]) {
  // Allow unit test execution from anywhere in the osquery source/build tree.
  while (osquery::kTestDataPath != "/") {
    if (!fs::exists(osquery::kTestDataPath)) {
      osquery::kTestDataPath =
          osquery::kTestDataPath.substr(3, osquery::kTestDataPath.size());
    } else {
      break;
    }
  }

  osquery::initTesting();
  testing::InitGoogleTest(&argc, argv);
  // Optionally enable Goggle Logging
  // google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
