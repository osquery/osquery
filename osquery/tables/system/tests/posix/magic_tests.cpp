/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <array>
#include <cstdint>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/tables/system/posix/magic.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

namespace {

constexpr std::uint32_t kMagicNumber = 0xF11E041C;
constexpr std::uint32_t kSupportedVersion = 18;

std::uint32_t swapBytes(std::uint32_t value) {
  return ((value & 0x000000FFU) << 24) | ((value & 0x0000FF00U) << 8) |
         ((value & 0x00FF0000U) >> 8) | ((value & 0xFF000000U) >> 24);
}

} // namespace

class MagicTests : public testing::Test {
 protected:
  void SetUp() override {
    dir_ = fs::temp_directory_path() /
           fs::unique_path("osquery.tests.magic.%%%%.%%%%");
    ASSERT_TRUE(fs::create_directories(dir_));
  }

  void TearDown() override {
    fs::remove_all(dir_);
  }

  // Writes the header of a compiled database and some bytes after it, which
  // libmagic would report as unparsable rules if it read them as source.
  std::string writeCompiled(const std::string& name,
                            std::uint32_t version,
                            bool other_byte_order = false) {
    std::array<std::uint32_t, 2> header{kMagicNumber, version};
    if (other_byte_order) {
      header = {swapBytes(kMagicNumber), swapBytes(version)};
    }

    auto path = (dir_ / name).string();
    std::ofstream stream(path, std::ios::binary);
    stream.write(reinterpret_cast<const char*>(header.data()), sizeof(header));
    stream << std::string(64, '\x7f');
    return path;
  }

  std::string writeRules(const std::string& name) {
    auto path = (dir_ / name).string();
    std::ofstream stream(path);
    stream << "0\tstring\tOSQUERYTEST\tosquery test file\n";
    return path;
  }

  fs::path dir_;
};

TEST_F(MagicTests, test_compiled_supported_version) {
  auto path = writeCompiled("db.mgc", kSupportedVersion);
  EXPECT_TRUE(isLoadableMagicDatabase(path, kSupportedVersion));

  // libmagic maps db.mgc for the entry db
  EXPECT_TRUE(
      isLoadableMagicDatabase((dir_ / "db").string(), kSupportedVersion));
}

TEST_F(MagicTests, test_compiled_other_version) {
  auto path = writeCompiled("db.mgc", 16);
  EXPECT_FALSE(isLoadableMagicDatabase(path, kSupportedVersion));
  EXPECT_FALSE(
      isLoadableMagicDatabase((dir_ / "db").string(), kSupportedVersion));
}

TEST_F(MagicTests, test_compiled_other_byte_order) {
  auto path = writeCompiled("supported.mgc", kSupportedVersion, true);
  EXPECT_TRUE(isLoadableMagicDatabase(path, kSupportedVersion));

  path = writeCompiled("other.mgc", 16, true);
  EXPECT_FALSE(isLoadableMagicDatabase(path, kSupportedVersion));
}

TEST_F(MagicTests, test_other_version_next_to_rule_source) {
  // libmagic rejects rules.mgc and parses the rules file itself
  writeCompiled("rules.mgc", 16);
  auto rules = writeRules("rules");
  EXPECT_TRUE(isLoadableMagicDatabase(rules, kSupportedVersion));
  EXPECT_FALSE(isLoadableMagicDatabase(rules + ".mgc", kSupportedVersion));
}

TEST_F(MagicTests, test_rule_source) {
  EXPECT_TRUE(isLoadableMagicDatabase(writeRules("rules"), kSupportedVersion));

  // A Magdir-style directory of rule files
  auto magdir = dir_ / "Magdir";
  ASSERT_TRUE(fs::create_directory(magdir));
  EXPECT_TRUE(isLoadableMagicDatabase(magdir.string(), kSupportedVersion));
}

TEST_F(MagicTests, test_compiled_without_extension) {
  // libmagic only maps the name ending in .mgc, so it would parse this
  // compiled database as rule source, whatever its version.
  auto path = writeCompiled("db", kSupportedVersion);
  EXPECT_FALSE(isLoadableMagicDatabase(path, kSupportedVersion));
}

TEST_F(MagicTests, test_missing) {
  EXPECT_FALSE(isLoadableMagicDatabase((dir_ / "missing.mgc").string(),
                                       kSupportedVersion));
  EXPECT_FALSE(
      isLoadableMagicDatabase((dir_ / "missing").string(), kSupportedVersion));
}

} // namespace tables
} // namespace osquery
