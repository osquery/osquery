/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tests/test_util.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

void genNodePackage(const std::string& file, Row& r, Logger& logger);
void genNodeSiteDirectories(const std::string& site,
                            QueryData& results,
                            Logger& logger);

} // namespace tables
} // namespace osquery

namespace osquery {
namespace table_tests {

class NpmPackagesUnitTest : public testing::Test {
 protected:
  void SetUp() override {
    temp_dir_ = fs::temp_directory_path() /
                fs::unique_path("osquery_npm_test_%%%%-%%%%-%%%%-%%%%");
    fs::create_directories(temp_dir_);
  }

  void TearDown() override {
    if (fs::exists(temp_dir_)) {
      fs::remove_all(temp_dir_);
    }
  }

  // Helper to create a mock package.json file
  void createPackageJson(const fs::path& path, const std::string& content) {
    fs::create_directories(path.parent_path());
    writeTextFile(path.string(), content);
  }

  // Helper to create a scoped package structure
  void createScopedPackage(const std::string& scope,
                           const std::string& package_name,
                           const std::string& version) {
    auto package_path =
        temp_dir_ / "node_modules" / scope / package_name / "package.json";
    std::string package_json = R"({
  "name": ")" + scope + "/" + package_name +
                               R"(",
  "version": ")" + version + R"(",
  "description": "Test scoped package",
  "author": "Test Author",
  "license": "MIT"
})";
    createPackageJson(package_path, package_json);
  }

  // Helper to create a regular package structure
  void createRegularPackage(const std::string& package_name,
                            const std::string& version) {
    auto package_path =
        temp_dir_ / "node_modules" / package_name / "package.json";
    std::string package_json = R"({
  "name": ")" + package_name + R"(",
  "version": ")" + version + R"(",
  "description": "Test regular package",
  "author": "Test Author",
  "license": "MIT"
})";
    createPackageJson(package_path, package_json);
  }

  fs::path temp_dir_;
};

TEST_F(NpmPackagesUnitTest, test_scoped_package_detection) {
  GLOGLogger logger;

  // Create mock scoped packages
  createScopedPackage("@types", "node", "18.0.0");
  createScopedPackage("@angular", "core", "15.0.0");

  // Create mock regular packages
  createRegularPackage("express", "4.18.0");
  createRegularPackage("lodash", "4.17.21");

  // Create mock nested regular package that should NOT be found
  // because nested pattern only matches scoped packages with @ prefix
  createScopedPackage("nested", "package", "3.2.1");

  QueryData results;
  tables::genNodeSiteDirectories(temp_dir_.string(), results, logger);

  // We should find only 4 packages (2 scoped + 2 regular)
  // The nested/package should NOT be found
  EXPECT_EQ(results.size(), 4);

  // Check that we found both scoped and regular packages
  bool found_scoped_types_node = false;
  bool found_scoped_angular_core = false;
  bool found_regular_express = false;
  bool found_regular_lodash = false;

  for (const auto& row : results) {
    auto name = row.at("name");
    auto version = row.at("version");
    auto path = row.at("path");

    // Verify scoped packages
    if (name == "@types/node") {
      found_scoped_types_node = true;
      EXPECT_EQ(version, "18.0.0");
      // Check for platform-agnostic path containing package structure
      fs::path expected_path =
          fs::path("node_modules") / "@types" / "node" / "package.json";
      EXPECT_TRUE(path.find(expected_path.string()) != std::string::npos);
    } else if (name == "@angular/core") {
      found_scoped_angular_core = true;
      EXPECT_EQ(version, "15.0.0");
      fs::path expected_path =
          fs::path("node_modules") / "@angular" / "core" / "package.json";
      EXPECT_TRUE(path.find(expected_path.string()) != std::string::npos);
    }
    // Verify regular packages
    else if (name == "express") {
      found_regular_express = true;
      EXPECT_EQ(version, "4.18.0");
      fs::path expected_path =
          fs::path("node_modules") / "express" / "package.json";
      EXPECT_TRUE(path.find(expected_path.string()) != std::string::npos);
    } else if (name == "lodash") {
      found_regular_lodash = true;
      EXPECT_EQ(version, "4.17.21");
      fs::path expected_path =
          fs::path("node_modules") / "lodash" / "package.json";
      EXPECT_TRUE(path.find(expected_path.string()) != std::string::npos);
    } else {
      FAIL() << "Unexpected package found: " << name;
    }

    // Verify common fields based on package type
    if (name.find('@') == 0) {
      EXPECT_EQ(row.at("description"), "Test scoped package");
    } else {
      EXPECT_EQ(row.at("description"), "Test regular package");
    }

    // Ensure nested/package is NOT found (it should not match the patterns)
    EXPECT_NE(name, "nested/package") 
        << "nested/package should not be found by the search patterns";
    EXPECT_EQ(row.at("author"), "Test Author");
    EXPECT_EQ(row.at("license"), "MIT");
    EXPECT_EQ(row.at("directory"), temp_dir_.string());
  }

  // Ensure we found all expected packages
  EXPECT_TRUE(found_scoped_types_node)
      << "Did not find @types/node scoped package";
  EXPECT_TRUE(found_scoped_angular_core)
      << "Did not find @angular/core scoped package";
  EXPECT_TRUE(found_regular_express) << "Did not find express regular package";
  EXPECT_TRUE(found_regular_lodash) << "Did not find lodash regular package";
}

} // namespace table_tests
} // namespace osquery
