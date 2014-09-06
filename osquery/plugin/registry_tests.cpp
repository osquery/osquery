// Copyright 2004-present Facebook. All Rights Reserved.

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include "osquery/plugin/registry.h"

namespace osquery {
namespace plugin {

class RegistryTests : public testing::Test {};

TEST_F(RegistryTests, test_plugin) {
  auto registry = Registry::getInstance();
  std::vector<std::string> results;
  std::vector<std::string> expected_results;
  osquery::Status s;

  s = registry->checkState(results);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  results.clear();
  s = registry->checkState(results);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results, expected_results);
}
}
}

int main(int argc, char* argv[]) {
  int argc_ = 2;
  char** argv_ = (char**)malloc(2);
  argv_[0] = argv[0];
  const char plugin_path[] =
      "--plugin_path=/Users/marpaia/git/osquery/build/osquery/plugin/";
  argv_[1] = (char*)plugin_path;
  google::ParseCommandLineFlags(&argc_, &argv_, true);
  auto base = osquery::plugin::Registry::getInstance();
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
