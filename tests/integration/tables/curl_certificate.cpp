
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for curl_certificate
// Spec file: specs/curl_certificate.table

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
  // 1. Query data
  auto const data =
      execute_query("select * from curl_certificate where hostname = ''");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"hostname", NormalType}
  //      {"common_name", NormalType}
  //      {"organization", NormalType}
  //      {"organization_unit", NormalType}
  //      {"serial_number", NormalType}
  //      {"issuer_common_name", NormalType}
  //      {"issuer_organization", NormalType}
  //      {"issuer_organization_unit", NormalType}
  //      {"valid_from", NormalType}
  //      {"valid_to", NormalType}
  //      {"sha256_fingerprint", NormalType}
  //      {"sha1_fingerprint", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
