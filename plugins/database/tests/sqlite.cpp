/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/database/tests/test_utils.h>

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
