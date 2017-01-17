/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <gtest/gtest.h>

#include <boost/filesystem/operations.hpp>

#include <osquery/database.h>
#include <osquery/flags.h>

#include "osquery/tests/test_util.h"

/// The following test macros allow pretty test output.
#define CREATE_DATABASE_TESTS(n)                                               \
  TEST_F(n, test_plugin_check) {                                               \
    testPluginCheck();                                                         \
  }                                                                            \
  TEST_F(n, test_reset) {                                                      \
    testReset();                                                               \
  }                                                                            \
  TEST_F(n, test_put) {                                                        \
    testPut();                                                                 \
  }                                                                            \
  TEST_F(n, test_get) {                                                        \
    testGet();                                                                 \
  }                                                                            \
  TEST_F(n, test_delete) {                                                     \
    testDelete();                                                              \
  }                                                                            \
  TEST_F(n, test_scan) {                                                       \
    testScan();                                                                \
  }                                                                            \
  TEST_F(n, test_scan_limit) {                                                 \
    testScanLimit();                                                           \
  }

namespace osquery {

DECLARE_string(database_path);

class DatabasePluginTests : public testing::Test {
 public:
  void SetUp() override {
    auto& rf = RegistryFactory::get();
    existing_plugin_ = rf.getActive("database");
    rf.plugin("database", existing_plugin_)->tearDown();

    setName(name());
    path_ = FLAGS_database_path;
    boost::filesystem::remove_all(path_);

    auto plugin = rf.plugin("database", getName());
    plugin_ = std::dynamic_pointer_cast<DatabasePlugin>(plugin);
    plugin_->reset();
  }

  void TearDown() override {
    auto& rf = RegistryFactory::get();
    rf.plugin("database", name_)->tearDown();
    rf.setActive("database", existing_plugin_);
  }

 protected:
  /// Path to testing database.
  std::string path_;

 protected:
  /// Require each plugin tester to implement a set name.
  virtual std::string name() = 0;

 private:
  void setName(const std::string& name) {
    name_ = name;
  }
  const std::string& getName() {
    return name_;
  }
  std::shared_ptr<DatabasePlugin> getPlugin() {
    return plugin_;
  }

 private:
  /// Plugin name
  std::string name_;

  /// Plugin casted from setUp, ready to run tests.
  std::shared_ptr<DatabasePlugin> plugin_{nullptr};

  /// Previous active database plugin.
  std::string existing_plugin_;

 protected:
  void testPluginCheck();
  void testReset();
  void testPut();
  void testGet();
  void testDelete();
  void testScan();
  void testScanLimit();
};
}
