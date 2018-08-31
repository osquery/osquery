
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for apt_sources
// Spec file: specs/posix/apt_sources.table

#include <osquery/logger.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace {

class AptSourcesTest : public IntegrationTableTest {};

TEST_F(AptSourcesTest, sanity) {
  QueryData data = execute_query("select * from apt_sources");
  if (data.empty()) {
    LOG(WARNING) << "select from \"apt_sources\" table returned no results and "
                    "therefore won't be tested";
  } else {
    auto const row_map = ValidatatioMap{
        {"name", NonEmptyString},
        {"source", FileOnDisk},
        {"base_uri", NonEmptyString},
        {"release", NonEmptyString},
        {"version", NonEmptyString},
        {"maintainer", NonEmptyString},
        {"components", NonEmptyString},
        {"architectures", NonEmptyString},
    };
    validate_rows(data, row_map);
  }
}

} // namespace
} // namespace osquery
