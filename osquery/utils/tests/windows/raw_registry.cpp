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
  std::vector<int> offset_tracker;
  parseHiveCell(
      reg_contents, offset, raw_reg, key_path, name_key, offset_tracker);
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
  std::vector<int> offset_tracker;

  parseHiveLeafHash(
      reg_contents, offset, raw_reg, key_path, name_key, offset_tracker);

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

TEST_F(RawRegistryTests, test_data_value) {
  auto test = getEnvVar("TEST_CONF_FILES_DIR");
  if (!test.is_initialized()) {
    FAIL();
  }
  auto const test_filepath =
      boost::filesystem::path(*test + "/windows/registry/NTUSER.DAT")
          .make_preferred()
          .string();

  int offset = 13896;
  std::string reg_type = "REG_SZ";
  int size = 76;
  std::ifstream input_file(test_filepath, std::ios::in | std::ios::binary);
  std::vector<char> reg_contents((std::istreambuf_iterator<char>(input_file)),
                                 (std::istreambuf_iterator<char>()));
  input_file.close();
  std::vector<int> offset_tracker;

  std::string value =
      parseDataValue(reg_contents, offset, size, reg_type, offset_tracker);
  ASSERT_TRUE(value == "Microsoft.Messaging_8wekyb3d8bbwe!App");
}

TEST_F(RawRegistryTests, test_leaf_index_cell) {
  auto test = getEnvVar("TEST_CONF_FILES_DIR");
  if (!test.is_initialized()) {
    FAIL();
  }
  auto const test_filepath =
      boost::filesystem::path(*test + "/windows/amcache/Amcache.hve")
          .make_preferred()
          .string();

  std::vector<RegTableData> raw_reg;
  std::vector<std::string> key_path;

  int offset = 3161132;
  RegNameKey name_key;
  std::ifstream input_file(test_filepath, std::ios::in | std::ios::binary);
  std::vector<char> reg_contents((std::istreambuf_iterator<char>(input_file)),
                                 (std::istreambuf_iterator<char>()));
  input_file.close();
  std::vector<int> offset_tracker;

  parseHiveLeafIndex(
      reg_contents, offset, raw_reg, key_path, name_key, offset_tracker);
  if (raw_reg.size() != 36844) {
    FAIL();
  }

  ASSERT_TRUE(raw_reg[105].key_path ==
              "aapt2.exe|7d6d93513d5fb4e0\\ProductName");
  ASSERT_TRUE(raw_reg[112].modified_time == 1632005732);
  ASSERT_TRUE(raw_reg[124].key == "aapt2.exe|d6af3824d6879fce");
  ASSERT_TRUE(raw_reg[139].key_type == "REG_SZ");
  ASSERT_TRUE(raw_reg[140].key_data == "0");
  ASSERT_TRUE(raw_reg[157].key_name == "OriginalFileName");
}

TEST_F(RawRegistryTests, test_value_key_list_cell) {
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

  int offset = 29504;
  int values = 11;
  RegNameKey name_key;
  std::ifstream input_file(test_filepath, std::ios::in | std::ios::binary);
  std::vector<char> reg_contents((std::istreambuf_iterator<char>(input_file)),
                                 (std::istreambuf_iterator<char>()));
  input_file.close();
  std::vector<int> offset_tracker;

  parseValueKeyList(reg_contents,
                    values,
                    offset,
                    raw_reg,
                    key_path,
                    name_key,
                    offset_tracker);

  ASSERT_TRUE(raw_reg.size() == 11);
  ASSERT_TRUE(raw_reg[3].key_path == "LeaveOnWithMouse");
  ASSERT_TRUE(raw_reg[8].key_type == "REG_DWORD");
  ASSERT_TRUE(raw_reg[10].key_data == "1");
  ASSERT_TRUE(raw_reg[3].key_name == "LeaveOnWithMouse");
}

TEST_F(RawRegistryTests, test_name_key_cell) {
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

  int offset = 5052;
  std::ifstream input_file(test_filepath, std::ios::in | std::ios::binary);
  std::vector<char> reg_contents((std::istreambuf_iterator<char>(input_file)),
                                 (std::istreambuf_iterator<char>()));
  input_file.close();
  std::vector<int> offset_tracker;

  parseNameKey(reg_contents, offset, raw_reg, key_path, offset_tracker);
  if (raw_reg.size() != 3) {
    FAIL();
  }
  ASSERT_TRUE(raw_reg[1].key_path == "Environment\\TEMP");
  ASSERT_TRUE(raw_reg[2].modified_time == 1552971338);
  ASSERT_TRUE(raw_reg[2].key == "Environment");
  ASSERT_TRUE(raw_reg[1].key_type == "REG_EXPAND_SZ");
  ASSERT_TRUE(raw_reg[2].key_data == "%USERPROFILE%\\AppData\\Local\\Temp");
  ASSERT_TRUE(raw_reg[2].key_name == "TMP");
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
  std::vector<int> offset_tracker;

  RegHiveBin hive_bin = parseHiveBin(reg_contents, offset, offset_tracker);

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