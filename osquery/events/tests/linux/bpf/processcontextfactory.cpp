/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "bpftestsmain.h"
#include "mockedfilesystem.h"
#include "utils.h"

#include <osquery/events/linux/bpf/processcontextfactory.h>

namespace osquery {

TEST_F(ProcessContextFactoryTests, captureSingleProcess) {
  MockedFilesystem mocked_filesystem;

  ProcessContext process_context;
  auto succeeded = ProcessContextFactory::captureSingleProcess(
      mocked_filesystem, process_context, 1234567);

  EXPECT_FALSE(succeeded);

  process_context = {};
  succeeded = ProcessContextFactory::captureSingleProcess(
      mocked_filesystem, process_context, 1001);

  EXPECT_TRUE(succeeded);

  EXPECT_EQ(process_context.parent_process_id, 3616);
  EXPECT_EQ(process_context.binary_path, "/usr/bin/zsh");

  ASSERT_EQ(process_context.argv.size(), 3U);
  EXPECT_EQ(process_context.argv.at(0), "zsh");
  EXPECT_EQ(process_context.argv.at(1), "-i");
  EXPECT_EQ(process_context.argv.at(2), "-H");

  EXPECT_EQ(process_context.cwd, "/home/alessandro");

  ASSERT_EQ(process_context.fd_map.size(), 2U);
  EXPECT_TRUE(
      validateFileDescriptor(process_context, 0xFFFFFF4, false, "/dev/pts/2"));

  EXPECT_TRUE(
      validateFileDescriptor(process_context, 0xFFFFFF5, false, "/dev/pts/3"));
}

TEST_F(ProcessContextFactoryTests, captureAllProcesses) {
  MockedFilesystem mocked_filesystem;
  ProcessContextMap process_context_map;
  auto succeeded = ProcessContextFactory::captureAllProcesses(
      mocked_filesystem, process_context_map);

  EXPECT_TRUE(succeeded);
  ASSERT_EQ(process_context_map.size(), 1U);
}

TEST_F(ProcessContextFactoryTests, getArgvFromCmdlineFile) {
  MockedFilesystem mocked_filesystem;

  std::vector<std::string> argv;
  auto succeeded = ProcessContextFactory::getArgvFromCmdlineFile(
      mocked_filesystem, argv, 0xFFFFFF8);

  EXPECT_TRUE(succeeded);

  ASSERT_EQ(argv.size(), 3U);
  EXPECT_EQ(argv.at(0), "zsh");
  EXPECT_EQ(argv.at(1), "-i");
  EXPECT_EQ(argv.at(2), "-H");
}

TEST_F(ProcessContextFactoryTests, getParentPidFromStatFile) {
  MockedFilesystem mocked_filesystem;

  pid_t parent_pid{-1};
  auto succeeded = ProcessContextFactory::getParentPidFromStatFile(
      mocked_filesystem, parent_pid, 0xFFFFFF9);

  EXPECT_TRUE(succeeded);
}

} // namespace osquery
