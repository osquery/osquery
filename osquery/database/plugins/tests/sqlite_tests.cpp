/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/database/tests/plugin_tests.h"

namespace osquery {

class SQLiteDatabasePluginTests : public DatabasePluginTests {
 protected:
  std::string name() override {
    return "sqlite";
  }
};

// Define the default set of database plugin operation tests.
CREATE_DATABASE_TESTS(SQLiteDatabasePluginTests);
}
