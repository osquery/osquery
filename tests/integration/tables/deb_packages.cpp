/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for deb_packages
// Spec file: specs/linux/deb_packages.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/logger.h>

namespace osquery {
namespace table_tests {

class DebPackages : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(DebPackages, test_sanity) {
  QueryData rows = execute_query("select * from deb_packages");
  if (rows.size() > 0) {
    ValidatatioMap row_map = {
        {"name", NonEmptyString},
        {"version", NonEmptyString},
        {"source", NormalType},
        {"size", IntType},
        {"arch", NonEmptyString},
        {"revision", NormalType},
    };
    validate_rows(rows, row_map);

    auto all_packages = std::unordered_set<std::string>{};
    for (const auto& row : rows) {
      auto pckg_name = row.at("name");
      all_packages.insert(pckg_name);
    }

    ASSERT_EQ(all_packages.count("dpkg"), 1u);
    ASSERT_EQ(all_packages.count("linux-base"), 1u);
    ASSERT_EQ(all_packages.count("linux-firmware"), 1u);
    ASSERT_EQ(all_packages.count("linux-generic"), 1u);

  } else {
    LOG(WARNING) << "Empty results of query from 'deb_packages', assume there "
                    "is no dpkg in the system";
  }
}

} // namespace table_tests
} // namespace osquery
