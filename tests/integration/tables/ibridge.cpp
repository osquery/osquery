/**
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for ibridge
// Spec file: specs/darwin/ibridge_info.table

#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class IBridgeTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(IBridgeTest, test_sanity) {
  auto rows = execute_query("select * from ibridge_info");
  if (rows.empty()) {
    VLOG(1) << "Empty result for table: ibridge, skipping test";
  } else {
    ASSERT_EQ(rows.size(), 1ul);
    ValidationMap validation_map = {
        {"boot_uuid", NormalType},
        {"coprocessor_version", NonEmptyString},
        {"firmware_version", NonEmptyString},
        {"unique_chip_id", NonEmptyString},
    };
    validate_rows(rows, validation_map);
  }
}

} // namespace table_tests
} // namespace osquery
