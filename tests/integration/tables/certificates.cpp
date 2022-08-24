/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for certificates
// Spec file: specs/macwin/certificates.table

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/tests/test_util.h>
#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {

class certificates : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }

#ifdef OSQUERY_WINDOWS
  static void SetUpTestSuite() {
    initUsersAndGroupsServices(true, false);
  }

  static void TearDownTestSuite() {
    Dispatcher::stopServices();
    Dispatcher::joinServices();
    deinitUsersAndGroupsServices(true, false);
    Dispatcher::instance().resetStopping();
  }
#endif
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

TEST_F(certificates, test_certificate_common_name) {
  const auto data =
      execute_query("SELECT common_name FROM certificates LIMIT 1");
  ASSERT_GE(data.size(), 1uL);
  std::map<std::string, std::string> row = data[0];
  const std::string value = row["common_name"];
  ASSERT_FALSE(value.empty());
}

} // namespace table_tests
} // namespace osquery
