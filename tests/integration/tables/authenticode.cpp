/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for authenticode
// Spec file: specs/windows/authenticode.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class authenticode : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(authenticode, test_sanity) {
  // notepad.exe is universally present on Windows and is Authenticode-signed
  // by Microsoft with an SPC_SP_OPUS_INFO publisher info blob that carries a
  // non-empty pwszProgramName. Asserting original_program_name is non-empty
  // also guards against regression of GHSA-hr28-jvpx-68cx, where the wrong
  // output buffer was passed to CryptDecodeObject and the program name was
  // silently always empty.
  auto const data = execute_query(
      "select * from authenticode "
      "where path = 'C:\\Windows\\System32\\notepad.exe'");

  ASSERT_EQ(data.size(), 1ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"original_program_name", NonEmptyString},
      {"serial_number", NonEmptyString},
      {"issuer_name", NonEmptyString},
      {"subject_name", NonEmptyString},
      {"result", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
