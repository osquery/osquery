/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/tests/test_utils.h>

#include <osquery/filesystem/filesystem.h>

#include <osquery/utils/system/env.h>

#include <gtest/gtest.h>

#include <boost/io/quoted.hpp>

#include <cstdlib>

namespace {

namespace fs = boost::filesystem;

fs::path getConfDirPathImpl() {
  char const* kEnvVarName = "TEST_CONF_FILES_DIR";
  auto const value_opt = osquery::getEnvVar(kEnvVarName);
  EXPECT_TRUE(static_cast<bool>(value_opt))
      << "Env var " << boost::io::quoted(kEnvVarName) << " was not found, "
      << " looks like cxx_test argument 'env' is not set up.";
  return fs::path(value_opt.get());
}

fs::path getTestHelperScriptsDirectoryImpl() {
  char const* kEnvVarName = "TEST_HELPER_SCRIPTS_DIR";
  auto const value_opt = osquery::getEnvVar(kEnvVarName);
  EXPECT_TRUE(static_cast<bool>(value_opt))
      << "Env var " << boost::io::quoted(kEnvVarName) << " was not found, "
      << " looks like cxx_test argument 'env' is not set up.";
  return fs::path(value_opt.get());
}
}

namespace osquery {

fs::path const& getTestConfigDirectory() {
    static auto const path = getConfDirPathImpl();
    return path;
}

fs::path const& getTestHelperScriptsDirectory() {
  static auto const path = getTestHelperScriptsDirectoryImpl();
  return path;
}

std::map<std::string, std::string> getTestConfigMap(const std::string& file) {
  std::string content;
  auto const filepath = getTestConfigDirectory() / file;
  auto status = readFile(filepath, content);
  EXPECT_TRUE(status.ok())
      << "Could not read file: " << boost::io::quoted(filepath.string())
      << ", because: " << status.what();
  std::map<std::string, std::string> config;
  config["awesome"] = content;
  return config;
}

JSON getExamplePacksConfig() {
  std::string content;
  auto const filepath = getTestConfigDirectory() / "test_inline_pack.conf";
  auto status = readFile(filepath, content);
  EXPECT_TRUE(status.ok())
      << "Could not read file: " << boost::io::quoted(filepath.string())
      << ", because: " << status.what();
  JSON doc = JSON::newObject();
  doc.fromString(content);
  return doc;
}

/// no discovery queries, no platform restriction
JSON getUnrestrictedPack() {
  auto doc = getExamplePacksConfig();
  return JSON::newFromValue(doc.doc()["packs"]["unrestricted_pack"]);
}

// several restrictions (version, platform, shard)
JSON getRestrictedPack() {
  auto doc = getExamplePacksConfig();
  return JSON::newFromValue(doc.doc()["packs"]["restricted_pack"]);
}

/// 1 discovery query, darwin platform restriction
JSON getPackWithDiscovery() {
  auto doc = getExamplePacksConfig();
  return JSON::newFromValue(doc.doc()["packs"]["discovery_pack"]);
}

/// 1 discovery query which will always pass
JSON getPackWithValidDiscovery() {
  auto doc = getExamplePacksConfig();
  return JSON::newFromValue(doc.doc()["packs"]["valid_discovery_pack"]);
}

/// no discovery queries, no platform restriction, fake version string
JSON getPackWithFakeVersion() {
  auto doc = getExamplePacksConfig();
  return JSON::newFromValue(doc.doc()["packs"]["fake_version_pack"]);
}

} // namespace osquery
