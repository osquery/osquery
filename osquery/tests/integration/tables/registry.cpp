
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for registry
// Spec file: specs/windows/registry.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace {

class RegistryTest : public IntegrationTableTest {};

TEST_F(RegistryTest, sanity) {
  QueryData const rows = execute_query("select * from registry");
  ASSERT_GT(rows.size(), 0ul);
  auto const row_map = ValidatatioMap{
      {"key", NonEmptyString},
      {"path", NonEmptyString},
      {"name", NonEmptyString},
      {"type", NonEmptyString},
      {"data", NormalType},
      {"mtime", NonNegativeInt},
  };
  validate_rows(rows, row_map);
}

} // namespace
} // namespace osquery
