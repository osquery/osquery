// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/filesystem.h"

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>

#include "osquery/core.h"
#include "osquery/core/test_util.h"

using namespace osquery::core;
namespace pt = boost::property_tree;

namespace osquery {
namespace fs {

// run this benchmark with --iterations=9001 to parse over 9000 property lists
DEFINE_int32(iterations, 100, "Iterations to execute");

class PlistBenchmark : public testing::Test {};

TEST_F(PlistBenchmark, bench_parse_plist_content) {
  // using LOG(ERROR) as a quick hack so that gtest displays the log line even
  // when the test passes
  LOG(ERROR) << "Starting: " << getAsciiTime();
  LOG(ERROR) << "Performing " << FLAGS_iterations << " iterations";
  int time = getUnixTime();
  for (int i = 0; i < FLAGS_iterations; ++i) {
    std::string content = getPlistContent();
    pt::ptree tree;
    auto s = parsePlistContent(content, tree);
    EXPECT_TRUE(s.ok());
    EXPECT_EQ(s.toString(), "OK");
    EXPECT_EQ(tree.get<bool>("Disabled"), true);
    EXPECT_THROW(tree.get<bool>("foobar"), pt::ptree_bad_path);
    EXPECT_EQ(tree.get<std::string>("Label"), "com.apple.FileSyncAgent.sshd");
    std::vector<std::string> program_arguments = {
        "/System/Library/CoreServices/FileSyncAgent.app/Contents/Resources/"
        "FileSyncAgent_sshd-keygen-wrapper",
        "-i", "-f",
        "/System/Library/CoreServices/FileSyncAgent.app/Contents/Resources/"
        "FileSyncAgent_sshd_config", };
    pt::ptree program_arguments_tree = tree.get_child("ProgramArguments");
    std::vector<std::string> program_arguments_parsed;
    for (const auto& argument : program_arguments_tree) {
      program_arguments_parsed.push_back(argument.second.get<std::string>(""));
    }
    EXPECT_EQ(program_arguments_parsed, program_arguments);
  }
  LOG(ERROR) << "Ending:   " << getAsciiTime();
  LOG(ERROR) << "Benchmark executed in " << (getUnixTime() - time)
             << " seconds";
}
}
}

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
