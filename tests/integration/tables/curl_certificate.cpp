/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class curlCertificate : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(curlCertificate, test_sanity) {
  auto const data = execute_query(
      "select * from curl_certificate where hostname = 'www.github.com'");
  ASSERT_EQ(data.size(), 1ul);
  ValidationMap row_map = {{"hostname", NormalType},
                           {"common_name", NormalType},
                           {"organization", NormalType},
                           {"organization_unit", NormalType},
                           {"serial_number", NormalType},
                           {"issuer_common_name", NormalType},
                           {"issuer_organization", NormalType},
                           {"issuer_organization_unit", NormalType},
                           {"valid_from", NormalType},
                           {"valid_to", NormalType},
                           {"sha256_fingerprint", NormalType},
                           {"sha1_fingerprint", NormalType},
                           {"version", IntType},
                           {"signature_algorithm", NormalType},
                           {"signature", NormalType},
                           {"subject_key_identifier", NormalType},
                           {"authority_key_identifier", NormalType},
                           {"key_usage", NormalType},
                           {"extended_key_usage", NormalType},
                           {"policies", NormalType},
                           {"subject_alternative_names", NormalType},
                           {"issuer_alternative_names", NormalType},
                           {"info_access", NormalType},
                           {"subject_info_access", NormalType},
                           {"policy_mappings", NormalType},
                           {"has_expired", IntType},
                           {"basic_constraint", NormalType},
                           {"name_constraints", NormalType},
                           {"policy_constraints", NormalType},
                           {"pem", NormalType}};
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
