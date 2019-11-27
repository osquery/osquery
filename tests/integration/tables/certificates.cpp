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

#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {

class certificates : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(certificates, test_sanity) {
  auto const data = execute_query("select * from certificates");

  ASSERT_GE(data.size(), 1ul);

  ValidationMap row_map = {
      {"common_name", NormalType},
      {"subject", NormalType},
      {"issuer", NormalType},
      {"ca", IntType},
      {"self_signed", IntType},
      {"not_valid_before", NormalType},
      {"not_valid_after", NormalType},
      {"signing_algorithm", NormalType},
      {"key_algorithm", NormalType},
      {"key_strength", NormalType},
      {"key_usage", NormalType},
      {"subject_key_id", NormalType},
      {"authority_key_id", NormalType},
      {"sha1", NormalType},
      {"path", NormalType},
      {"serial", NormalType},
  };

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    row_map["sid"] = NormalType;
    row_map["store_location"] = NormalType;
    row_map["store"] = NormalType;
    row_map["username"] = NormalType;
    row_map["store_id"] = NormalType;
  }

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
