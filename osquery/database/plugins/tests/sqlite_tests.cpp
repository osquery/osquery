/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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
