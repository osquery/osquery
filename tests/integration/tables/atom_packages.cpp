/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for atom_packages
// Spec file: specs/atom_packages.table

#include <osquery/logger.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class atomPackages : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(atomPackages, test_sanity) {
  auto const data = execute_query("select * from atom_packages");
  if (data.empty()) {
    LOG(WARNING) << "Empty results of query from 'atom_packages', assume there "
                    "is no atom on the system";
    return;
  }

  ValidationMap row_map = {
      {"name", NormalType},
      {"version", NormalType},
      {"description", NormalType},
      {"path", NormalType},
      {"license", NormalType},
      {"homepage", NormalType},
      {"uid", IntType},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
