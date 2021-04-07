/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for startup_items
// Spec file: specs/macwin/startup_items.table

#include <osquery/tests/integration/tables/helper.h>

#include <boost/algorithm/string/join.hpp>
#include <map>
#include <vector>

namespace osquery {
namespace table_tests {

class StartupItemsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(StartupItemsTest, test_sanity) {
  auto const data = execute_query("select * from startup_items");

  ValidationMap row_map = {
      {"name", NonEmptyString},
      {"path", NormalType},
      {"args", NormalType},
      {"type", SpecificValuesCheck{"Startup Item", "systemd unit"}},
      {"source", NormalType},
      {"status", NonEmptyString},
      {"username", NormalType},
  };
  validate_rows(data, row_map);

  /* Check that the status column contains specific values which depend on the
   * type */
  std::vector<std::string> valid_systemd_status_values = {"active",
                                                          "inactive",
                                                          "failed",
                                                          "maintenance",
                                                          "reloading",
                                                          "activating",
                                                          "deactivating"};
  for (const auto& row : data) {
    if (row.at("type") == "Startup Item") {
      /* Startup Items are scripts or .desktop files, so if they're present in
       * the table it means they are enabled. There's no disabled state. */
      EXPECT_EQ(row.at("status"), "enabled");
    } else if (row.at("type") == "systemd unit") {
      auto status = std::find(valid_systemd_status_values.begin(),
                              valid_systemd_status_values.end(),
                              row.at("status"));
      EXPECT_NE(status, valid_systemd_status_values.end())
          << "Expected status to be one of "
          << boost::algorithm::join(valid_systemd_status_values, ", ")
          << ", but " << row.at("status") << " has been found";
    }
  }
}

} // namespace table_tests
} // namespace osquery
