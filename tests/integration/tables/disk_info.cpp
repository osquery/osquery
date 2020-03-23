/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for disk_info
// Spec file: specs/windows/disk_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class diskInfo : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(diskInfo, test_sanity) {
  auto const data = execute_query("select * from disk_info");
  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"partitions", NonNegativeInt},
      {"disk_index", NonNegativeInt},
      {"type", SpecificValuesCheck{"SCSI", "HDC", "IDE", "USB", "1394"}},
      {"id", NonEmptyString},
      {"pnp_device_id", NonEmptyString},
      {"disk_size", NonNegativeInt | NonZero},
      {"manufacturer", NormalType},
      {"hardware_model", NormalType},
      {"name", NormalType},
      {"serial", NormalType},
      {"description", NormalType}};

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
