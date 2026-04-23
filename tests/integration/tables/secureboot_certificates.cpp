/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity-check integration test for secureboot_certificates
// Spec file: specs/linux/secureboot_certificates.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/utils/info/platform_type.h>

#include <boost/filesystem.hpp>

namespace osquery::table_tests {

class SecurebootCertificates : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(SecurebootCertificates, test_sanity) {
  auto const data =
      execute_query("SELECT * FROM secureboot_certificates");

  if (!boost::filesystem::exists("/sys/firmware/efi/efivars")) {
    // No EFI variables available — query must succeed and return no rows.
    EXPECT_TRUE(data.empty());
    return;
  }

  // At least one certificate was found: validate all columns.
  ValidationMap row_map = {
      {"common_name", NonEmptyString},
      {"subject", NonEmptyString},
      {"issuer", NonEmptyString},
      {"not_valid_before", NonNegativeInt},
      {"not_valid_after", NonNegativeInt},
      {"sha1", NonEmptyString},
      {"serial", NonEmptyString},
      {"store", SpecificValuesCheck({"db", "dbx"})},
      {"path", FileOnDisk},
      {"is_ca", Bool},
      {"self_signed", Bool},
      {"key_usage", NormalType},
      {"authority_key_id", NormalType},
      {"subject_key_id", NormalType},
      {"signing_algorithm", NonEmptyString},
      {"key_algorithm", NonEmptyString},
      {"key_strength", NonEmptyString},
  };

  validate_rows(data, row_map);
}

} // namespace osquery::table_tests
