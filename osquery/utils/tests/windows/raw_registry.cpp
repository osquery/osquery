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

#include <iostream>
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
  if (raw_reg.size() != 1404) {
    FAIL();
  }

  ASSERT_TRUE(raw_reg[0].key_path == "ROOT");
  ASSERT_TRUE(raw_reg[8].modified_time == 1552971338);
  ASSERT_TRUE(raw_reg[3].key == "ROOT\\AppEvents\\EventLabels\\.Default");
  ASSERT_TRUE(raw_reg[5].key_type == "REG_SZ");
  ASSERT_TRUE(raw_reg[7].key_data == "Program Error");
  ASSERT_TRUE(raw_reg[9].key_name == "(default)");
}

TEST_F(RawRegistryTests, test_leaf_hash_cell) {
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

  int offset = 10668;
  RegNameKey name_key;
  std::ifstream input_file(test_filepath, std::ios::in | std::ios::binary);
  std::vector<char> reg_contents((std::istreambuf_iterator<char>(input_file)),
                                 (std::istreambuf_iterator<char>()));
  input_file.close();

  parseHiveLeafHash(reg_contents, offset, raw_reg, key_path, name_key);

  if (raw_reg.size() != 20) {
    FAIL();
  }

  ASSERT_TRUE(raw_reg[4].key_path == "SysEventParameters\\FlickTolerance");
  ASSERT_TRUE(raw_reg[7].modified_time == 1552971338);
  ASSERT_TRUE(raw_reg[15].key == "SysEventParameters\\FlickCommands");
  ASSERT_TRUE(raw_reg[16].key_type == "REG_SZ");
  ASSERT_TRUE(raw_reg[18].key_data == "{00000000-0000-0000-0000-000000000000}");
  ASSERT_TRUE(raw_reg[19].key_name == "upRight");
}

TEST_F(RawRegistryTests, test_hive_bin) {
  auto test = getEnvVar("TEST_CONF_FILES_DIR");
  if (!test.is_initialized()) {
    FAIL();
  }
  auto const test_filepath =
      boost::filesystem::path(*test + "/windows/registry/NTUSER.DAT")
          .make_preferred()
          .string();

  int offset = 4096;
  std::ifstream input_file(test_filepath, std::ios::in | std::ios::binary);
  std::vector<char> reg_contents((std::istreambuf_iterator<char>(input_file)),
                                 (std::istreambuf_iterator<char>()));
  input_file.close();

  RegHiveBin hive_bin = parseHiveBin(reg_contents, offset);

  ASSERT_TRUE(hive_bin.sig == 1852400232);
  ASSERT_TRUE(hive_bin.size == 4096);
  ASSERT_TRUE(hive_bin.timestamp == 0);
  ASSERT_TRUE(hive_bin.offset == 0);
}

TEST_F(RawRegistryTests, test_raw_registry) {
  auto test = getEnvVar("TEST_CONF_FILES_DIR");
  if (!test.is_initialized()) {
    FAIL();
  }
  std::string test_filepath =
      boost::filesystem::path(*test + "/windows/registry/NTUSER.DAT")
          .make_preferred()
          .string();
  cleanRegPath(test_filepath);

  std::vector<RegTableData> raw_reg =
      rawRegistry(test_filepath, "\\\\.\\PHYSICALDRIVE0");
  if (raw_reg.size() != 1404) {
    FAIL();
  }

  ASSERT_TRUE(raw_reg[29].key_path ==
              "ROOT\\AppEvents\\EventLabels\\FaxBeep\\(default)");
  ASSERT_TRUE(raw_reg[34].modified_time == 1571637420);
  ASSERT_TRUE(raw_reg[47].key == "ROOT\\AppEvents\\EventLabels\\MenuPopup");
  ASSERT_TRUE(raw_reg[51].key_type == "REG_SZ");
  ASSERT_TRUE(raw_reg[62].key_data == "@mmres.dll,-5863");
  ASSERT_TRUE(raw_reg[78].key_name == "(default)");
}
} // namespace osquery