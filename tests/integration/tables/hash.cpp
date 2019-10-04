/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for hash
// Spec file: specs/hash.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/utils/info/platform_type.h>

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
  const std::string query = std::string{"select * from hash where path = '"} +
                            path.string() + std::string{"'"};

  QueryData data = execute_query(query);

  ASSERT_EQ(data.size(), 1ul);

  ValidatatioMap row_map = {
      {"path", NonEmptyString},
      {"directory", NonEmptyString},
      {"md5", NonEmptyString},
      {"sha1", NonEmptyString},
      {"sha256", NonEmptyString},
  };

  if (isPlatform(PlatformType::TYPE_POSIX)) {
    row_map.emplace("ssdeep", NonEmptyString);
  }

  ASSERT_EQ(data[0]["path"], path.string());
  ASSERT_EQ(data[0]["directory"], path.parent_path().string());
  ASSERT_EQ(data[0]["md5"], "35899082e51edf667f14477ac000cbba");
  ASSERT_EQ(data[0]["sha1"], "e7505beb754bed863e3885f73e3bb6866bdd7f8c");
  ASSERT_EQ(data[0]["sha256"],
            "a58dd8680234c1f8cc2ef2b325a43733605a7f16f288e072de8eae81fd8d6433");
  if (isPlatform(PlatformType::TYPE_POSIX)) {
    ASSERT_EQ(data[0]["ssdeep"], "3:f4oo8MRwRJFGW1gC64:f4kPvtHF");
  }

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
