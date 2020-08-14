/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/filesystem.h>
#include <osquery/logger/logger.h>

#include "osquery/tests/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {

// run this benchmark with --iterations=9001 to parse over 9000 property lists
FLAG(int32, plist_iterations, 100, "Iterations to execute plist benchmark");

class PlistBenchmark : public testing::Test {};

TEST_F(PlistBenchmark, bench_parse_plist_content) {
  // using LOG(ERROR) as a quick hack so that gtest displays the log line even
  // when the test passes
  LOG(ERROR) << "Starting: " << getAsciiTime();
  LOG(ERROR) << "Performing " << FLAGS_plist_iterations << " iterations";
  int time = getUnixTime();
  for (int i = 0; i < FLAGS_plist_iterations; ++i) {
    std::string content;
    readFile(kTestDataPath + "test.plist", content);

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
        "-i",
        "-f",
        "/System/Library/CoreServices/FileSyncAgent.app/Contents/Resources/"
        "FileSyncAgent_sshd_config",
    };
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

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
