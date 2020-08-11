/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tables/system/windows/userassist.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {
class UserassistTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST(Rot13Test, DecodeData) {
  std::string encoded_data = "Gur dhvpx oebja sbk whzcf bire gur ynml qbt";
  std::string decoded_data = tables::rotDecode(encoded_data);
  ASSERT_TRUE(decoded_data == "The quick brown fox jumps over the lazy dog");
}

TEST_F(UserassistTest, test_sanity) {
  QueryData const rows = execute_query("select * from userassist");
  QueryData const specific_query_rows =
      execute_query("select * from userassist where path is 'UEME_CTLSESSION'");

  ASSERT_GT(rows.size(), 0ul);
  ASSERT_GT(specific_query_rows.size(), 0ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"last_execution_time", NormalType},
      {"count", NormalType},
      {"sid", NonEmptyString},
  };
  validate_rows(rows, row_map);
  validate_rows(specific_query_rows, row_map);
}
} // namespace table_tests
} // namespace osquery
