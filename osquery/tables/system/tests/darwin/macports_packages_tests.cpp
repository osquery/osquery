/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <gtest/gtest.h>

#include <osquery/core/sql/query_data.h>
#include <osquery/core/tables.h>
#include <osquery/sql/sqlite_util.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

void portsFromPrefix(QueryData& results,
                     const std::string& prefix,
                     bool userRequested);

class MacPortsPackagesTests : public testing::Test {
 protected:
  void SetUp() override {
    prefix_ = fs::temp_directory_path() / fs::unique_path();
    auto registry_dir = prefix_ / "var" / "macports" / "registry";
    ASSERT_TRUE(fs::create_directories(registry_dir));
    registry_ = (registry_dir / "registry.db").string();

    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open(registry_.c_str(), &db), SQLITE_OK);

    // A cut-down copy of the MacPorts registry schema: only the columns the
    // table reads, in the types MacPorts uses.
    const char* schema =
        "CREATE TABLE ports ("
        "  name TEXT, version TEXT, revision INTEGER, variants TEXT,"
        "  archs TEXT, requested INTEGER, date DATETIME, state TEXT);"
        // An explicitly requested port.
        "INSERT INTO ports VALUES"
        "  ('jq', '1.8.2', 0, '', 'arm64', 1, 1757000000, 'installed');"
        // A dependency, with variants, to check they survive verbatim.
        "INSERT INTO ports VALUES"
        "  ('cctools', '949.0.1', 3, '+xcode', 'arm64', 0, 1757000001,"
        "   'installed');"
        // Deactivated: unpacked into the image directory but not linked into
        // the prefix, so the table must not report it.
        "INSERT INTO ports VALUES"
        "  ('ghosted', '1.0', 0, '', 'arm64', 1, 1757000002, 'imaged');";
    char* err = nullptr;
    ASSERT_EQ(sqlite3_exec(db, schema, nullptr, nullptr, &err), SQLITE_OK);
    sqlite3_close(db);
  }

  void TearDown() override {
    boost::system::error_code ec;
    fs::remove_all(prefix_, ec);
  }

  fs::path prefix_;
  std::string registry_;
};

TEST_F(MacPortsPackagesTests, test_only_installed_ports_are_returned) {
  QueryData results;
  portsFromPrefix(results, prefix_.string(), true);

  ASSERT_EQ(results.size(), 2U);
  for (const auto& row : results) {
    EXPECT_NE(row.at("name"), "ghosted");
  }
}

TEST_F(MacPortsPackagesTests, test_columns_are_mapped) {
  QueryData results;
  portsFromPrefix(results, prefix_.string(), true);
  ASSERT_EQ(results.size(), 2U);

  const Row* jq = nullptr;
  for (const auto& row : results) {
    if (row.at("name") == "jq") {
      jq = &row;
    }
  }
  ASSERT_NE(jq, nullptr);

  EXPECT_EQ(jq->at("version"), "1.8.2");
  EXPECT_EQ(jq->at("revision"), "0");
  EXPECT_EQ(jq->at("requested"), "1");
  // The registry column is `archs`; the table exposes `arch`.
  EXPECT_EQ(jq->at("arch"), "arm64");
  EXPECT_EQ(jq->count("archs"), 0U);
  // Every row carries the prefix it was read from.
  EXPECT_EQ(jq->at("prefix"), prefix_.string());
}

TEST_F(MacPortsPackagesTests, test_variants_survive_verbatim) {
  QueryData results;
  portsFromPrefix(results, prefix_.string(), true);

  const Row* cctools = nullptr;
  for (const auto& row : results) {
    if (row.at("name") == "cctools") {
      cctools = &row;
    }
  }
  ASSERT_NE(cctools, nullptr);
  EXPECT_EQ(cctools->at("variants"), "+xcode");
  EXPECT_EQ(cctools->at("revision"), "3");
  EXPECT_EQ(cctools->at("requested"), "0");
}

TEST_F(MacPortsPackagesTests, test_missing_registry_yields_no_rows) {
  QueryData results;
  auto absent = (fs::temp_directory_path() / fs::unique_path()).string();
  portsFromPrefix(results, absent, false);
  EXPECT_TRUE(results.empty());
}

} // namespace tables
} // namespace osquery
