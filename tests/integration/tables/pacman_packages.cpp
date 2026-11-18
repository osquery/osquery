/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for pacman_packages
// Spec file: specs/linux/pacman_packages.table

#include <unordered_set>

#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class PacmanPackages : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(PacmanPackages, test_sanity) {
  QueryData rows = execute_query("select * from pacman_packages");
  if (rows.size() > 0) {
    ValidationMap row_map = {
        {"name", NonEmptyString},
        {"version", NonEmptyString},
        {"source", NormalType},
        {"description", NormalType},
        {"url", NormalType},
        {"licenses", NormalType},
        {"groups", NormalType},
        {"arch", NonEmptyString},
        {"size", NonNegativeInt},
        {"packager", NormalType},
        {"build_time", NonNegativeInt},
        {"install_time", NonNegativeInt},
        {"install_reason", NormalType},
        {"validation", NormalType},
        {"dbpath", NonEmptyString},
    };

    validate_rows(rows, row_map);

    // pacman manages its own package, so a database that reports anything at
    // all reports this.
    auto all_packages = std::unordered_set<std::string>{};
    for (const auto& row : rows) {
      all_packages.insert(row.at("name"));
    }

    ASSERT_EQ(all_packages.count("pacman"), 1u);
  } else {
    LOG(WARNING) << "Empty results of query from 'pacman_packages', assume "
                    "there is no pacman in the system";
  }
}

} // namespace table_tests
} // namespace osquery
