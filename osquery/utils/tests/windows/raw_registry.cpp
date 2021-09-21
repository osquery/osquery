/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/env.h>
#include <osquery/utils/windows/raw_registry.h>

#include <boost/filesystem.hpp>
#include <gtest/gtest.h>

#include <vector>

namespace osquery {
class RawRegistryTests : public testing::Test {};

TEST_F(RawRegistryTests, test_hive_cell) {
  auto test = getEnvVar("TEST_CONF_FILES_DIR");
  if (!test.is_initialized()) {
    FAIL();
  }
  auto const test_filepath =
      boost::filesystem::path(*test + "/windows/registry/NTUSER.DAT")
          .make_preferred()
          .string();

  std::vector<RegTableData> raw_reg;
  std::vector<std::string> key_path;

  int offset = 32;
  RegNameKey name_key;
  std::ifstream input_file(test_filepath, std::ios::in | std::ios::binary);
  std::vector<char> reg_contents((std::istreambuf_iterator<char>(input_file)),
                                 (std::istreambuf_iterator<char>()));
  input_file.close();

  parseHiveCell(reg_contents, offset, raw_reg, key_path, name_key);
  if (reg_contents.size() != 262144) {
    FAIL();
  }
  ASSERT_TRUE(raw_reg[0].key_path == "ROOT");
  ASSERT_TRUE(raw_reg[8].modified_time == 1552971338);
  ASSERT_TRUE(raw_reg[3].key == "ROOT\\AppEvents\\EventLabels\\.Default");
  ASSERT_TRUE(raw_reg[5].key_type == "REG_SZ");
  ASSERT_TRUE(raw_reg[7].key_data == "Program Error");
  ASSERT_TRUE(raw_reg[9].key_name == "(default)");
}
} // namespace osquery