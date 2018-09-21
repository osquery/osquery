/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for hash
// Spec file: specs/hash.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

namespace fs = boost::filesystem;

class Hash : public testing::Test {
 public:
  void SetUp() override {
    setUpEnvironment();
    path = fs::temp_directory_path() /
           fs::unique_path("osquery.tests.file.hashes");

    auto fout = std::ofstream(path.native(), std::ios::out | std::ios::binary);
    fout << "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
  }

  void TearDown() override {
    fs::remove(path.native());
  }

  fs::path path;
};

TEST_F(Hash, test_sanity) {
  const std::string query =
      "select * from hash where path = '" + path.native() + "'";

  QueryData data = execute_query(query);

  ASSERT_EQ(data.size(), 1ul);

  ValidatatioMap row_map = {
      {"path", NonEmptyString},
      {"directory", NonEmptyString},
      {"md5", NonEmptyString},
      {"sha1", NonEmptyString},
      {"sha256", NonEmptyString},
      {"ssdeep", NonEmptyString},
  };

  ASSERT_EQ(data[0]["path"], path.native());
  ASSERT_EQ(data[0]["directory"], path.parent_path().native());
  ASSERT_EQ(data[0]["md5"], "35899082e51edf667f14477ac000cbba");
  ASSERT_EQ(data[0]["sha1"], "e7505beb754bed863e3885f73e3bb6866bdd7f8c");
  ASSERT_EQ(data[0]["sha256"],
            "a58dd8680234c1f8cc2ef2b325a43733605a7f16f288e072de8eae81fd8d6433");
  ASSERT_EQ(data[0]["ssdeep"], "3:f4oo8MRwRJFGW1gC64:f4kPvtHF");

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
