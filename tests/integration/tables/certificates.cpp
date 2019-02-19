
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for certificates
// Spec file: specs/macwin/certificates.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class certificates : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(certificates, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from certificates");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"common_name", NormalType}
  //      {"subject", NormalType}
  //      {"issuer", NormalType}
  //      {"ca", IntType}
  //      {"self_signed", IntType}
  //      {"not_valid_before", NormalType}
  //      {"not_valid_after", NormalType}
  //      {"signing_algorithm", NormalType}
  //      {"key_algorithm", NormalType}
  //      {"key_strength", NormalType}
  //      {"key_usage", NormalType}
  //      {"subject_key_id", NormalType}
  //      {"authority_key_id", NormalType}
  //      {"sha1", NormalType}
  //      {"path", NormalType}
  //      {"serial", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
