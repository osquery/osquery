
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for known_hosts
// Spec file: specs/posix/known_hosts.table

#include <osquery/logger.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace {

class KnownHostsTest : public IntegrationTableTest {};

TEST_F(KnownHostsTest, sanity) {
  QueryData const rows = execute_query("select * from known_hosts");
  if (rows.empty()) {
    LOG(WARNING) << "select from \"known_hosts\" table returned no results and "
                    "therefore won't be tested";
  } else {
    auto const row_map = ValidatatioMap{
        {"uid", IntType},
        {"key", NonEmptyString},
        {"key_file", FileOnDisk},
    };
    validate_rows(rows, row_map);
  }
}

} // namespace
} // namespace osquery
