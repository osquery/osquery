/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for ibridge
// Spec file: specs/darwin/ibridge.table

#include <osquery/logger.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class IBridgeTest : public IntegrationTableTest {};

TEST_F(IBridgeTest, test_sanity) {
  auto rows = execute_query("select * from ibridge");
  if (rows.empty()) {
    VLOG(1) << "Empty result for table: ibridge, skipping test";
  } else {
    ASSERT_EQ(rows.size(), 1ul);
    ValidatatioMap validation_map = {
        {"boot_uuid", NormalType},
        {"coprocessor_version", NonEmptyString},
        {"firmware_version", NonEmptyString},
        {"unique_chip_id", NonEmptyString},
    };
    validate_rows(rows, validation_map);
  }
}
} // namespace osquery
