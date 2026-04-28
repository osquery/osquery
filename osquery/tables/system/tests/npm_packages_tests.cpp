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
                            Logger& logger,
                            int max_depth);

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

  // Helper to create a nested regular package (inside another package)
  void createNestedRegularPackage(const fs::path& parent_pkg_path,
                                  const std::string& package_name,
                                  const std::string& version) {
    auto package_path =
        parent_pkg_path / "node_modules" / package_name / "package.json";
    std::string package_json = R"({
  "name": ")" + package_name + R"(",
  "version": ")" + version + R"(",
  "description": "Test nested package",
  "author": "Nested Author",
  "license": "ISC"
})";
    createPackageJson(package_path, package_json);
  }

  // Helper to create a nested scoped package (inside another package)
  void createNestedScopedPackage(const fs::path& parent_pkg_path,
                                 const std::string& scope,
                                 const std::string& package_name,
                                 const std::string& version) {
    auto package_path = parent_pkg_path / "node_modules" / scope /
                        package_name / "package.json";
    std::string package_json = R"({
  "name": ")" + scope + "/" + package_name +
                               R"(",
  "version": ")" + version + R"(",
  "description": "Test nested scoped package",
  "author": "Nested Author",
  "license": "ISC"
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
  tables::genNodeSiteDirectories(temp_dir_.string(), results, logger, 100);

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

TEST_F(NpmPackagesUnitTest, test_nested_package_detection) {
  GLOGLogger logger;

  // Create a top-level package
  createRegularPackage("express", "4.18.0");

  // Create nested regular package inside express
  auto express_path = temp_dir_ / "node_modules" / "express";
  createNestedRegularPackage(express_path, "body-parser", "1.20.0");

  // Create nested scoped package inside express
  createNestedScopedPackage(express_path, "@types", "express", "4.17.0");

  // Create deeply nested package (depth 2)
  auto body_parser_path = express_path / "node_modules" / "body-parser";
  createNestedRegularPackage(body_parser_path, "bytes", "3.1.0");

  QueryData results;
  tables::genNodeSiteDirectories(temp_dir_.string(), results, logger, 100);

  // Should find 4 packages: express (depth 0), body-parser (depth 1),
  // @types/express (depth 1), bytes (depth 2)
  EXPECT_EQ(results.size(), 4);

  bool found_express = false;
  bool found_body_parser = false;
  bool found_types_express = false;
  bool found_bytes = false;

  for (const auto& row : results) {
    auto name = row.at("name");
    auto depth = row.at("depth");

    if (name == "express") {
      found_express = true;
      EXPECT_EQ(depth, "0");
      EXPECT_EQ(row.at("version"), "4.18.0");
    } else if (name == "body-parser") {
      found_body_parser = true;
      EXPECT_EQ(depth, "1");
      EXPECT_EQ(row.at("version"), "1.20.0");
    } else if (name == "@types/express") {
      found_types_express = true;
      EXPECT_EQ(depth, "1");
      EXPECT_EQ(row.at("version"), "4.17.0");
    } else if (name == "bytes") {
      found_bytes = true;
      EXPECT_EQ(depth, "2");
      EXPECT_EQ(row.at("version"), "3.1.0");
    }

    // All packages should have the root directory as their directory
    EXPECT_EQ(row.at("directory"), temp_dir_.string());
  }

  EXPECT_TRUE(found_express) << "Did not find express at depth 0";
  EXPECT_TRUE(found_body_parser) << "Did not find body-parser at depth 1";
  EXPECT_TRUE(found_types_express) << "Did not find @types/express at depth 1";
  EXPECT_TRUE(found_bytes) << "Did not find bytes at depth 2";
}

TEST_F(NpmPackagesUnitTest, test_max_depth_zero_no_recursion) {
  GLOGLogger logger;

  // Create a top-level package with nested dependencies
  createRegularPackage("express", "4.18.0");
  auto express_path = temp_dir_ / "node_modules" / "express";
  createNestedRegularPackage(express_path, "body-parser", "1.20.0");

  QueryData results;
  // max_depth = 0 should only return top-level packages
  tables::genNodeSiteDirectories(temp_dir_.string(), results, logger, 0);

  // Should find only 1 package (express at depth 0)
  EXPECT_EQ(results.size(), 1);
  EXPECT_EQ(results[0].at("name"), "express");
  EXPECT_EQ(results[0].at("depth"), "0");
}

TEST_F(NpmPackagesUnitTest, test_max_depth_limits_recursion) {
  GLOGLogger logger;

  // Create packages at depths 0, 1, and 2
  createRegularPackage("pkg-depth-0", "1.0.0");

  auto depth0_path = temp_dir_ / "node_modules" / "pkg-depth-0";
  createNestedRegularPackage(depth0_path, "pkg-depth-1", "1.0.0");

  auto depth1_path = depth0_path / "node_modules" / "pkg-depth-1";
  createNestedRegularPackage(depth1_path, "pkg-depth-2", "1.0.0");

  // max_depth = 1 should return packages at depth 0 and 1, but not 2
  QueryData results;
  tables::genNodeSiteDirectories(temp_dir_.string(), results, logger, 1);

  EXPECT_EQ(results.size(), 2);

  bool found_depth_0 = false;
  bool found_depth_1 = false;

  for (const auto& row : results) {
    auto name = row.at("name");
    if (name == "pkg-depth-0") {
      found_depth_0 = true;
      EXPECT_EQ(row.at("depth"), "0");
    } else if (name == "pkg-depth-1") {
      found_depth_1 = true;
      EXPECT_EQ(row.at("depth"), "1");
    } else {
      FAIL() << "Unexpected package found: " << name
             << " (should not find depth 2 with max_depth=1)";
    }
  }

  EXPECT_TRUE(found_depth_0);
  EXPECT_TRUE(found_depth_1);
}

TEST_F(NpmPackagesUnitTest, test_nested_scoped_packages) {
  GLOGLogger logger;

  // Create a scoped top-level package
  createScopedPackage("@angular", "core", "15.0.0");

  // Create nested packages inside the scoped package
  auto angular_core_path = temp_dir_ / "node_modules" / "@angular" / "core";
  createNestedRegularPackage(angular_core_path, "rxjs", "7.8.0");
  createNestedScopedPackage(angular_core_path, "@angular", "common", "15.0.0");

  QueryData results;
  tables::genNodeSiteDirectories(temp_dir_.string(), results, logger, 100);

  EXPECT_EQ(results.size(), 3);

  bool found_angular_core = false;
  bool found_rxjs = false;
  bool found_angular_common = false;

  for (const auto& row : results) {
    auto name = row.at("name");
    if (name == "@angular/core") {
      found_angular_core = true;
      EXPECT_EQ(row.at("depth"), "0");
    } else if (name == "rxjs") {
      found_rxjs = true;
      EXPECT_EQ(row.at("depth"), "1");
    } else if (name == "@angular/common") {
      found_angular_common = true;
      EXPECT_EQ(row.at("depth"), "1");
    }
  }

  EXPECT_TRUE(found_angular_core) << "Did not find @angular/core at depth 0";
  EXPECT_TRUE(found_rxjs) << "Did not find rxjs at depth 1";
  EXPECT_TRUE(found_angular_common)
      << "Did not find @angular/common at depth 1";
}

} // namespace table_tests
} // namespace osquery
