/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <plugins/database/tests/utils.h>

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
