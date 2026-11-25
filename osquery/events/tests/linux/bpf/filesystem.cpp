/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "bpftestsmain.h"

#include <osquery/events/linux/bpf/ifilesystem.h>

#include <fcntl.h>

namespace osquery {

TEST_F(FilesystemTests, enumFilesDoesNotCloseTheDirectoryFd) {
  IFilesystem::Ref fs;
  ASSERT_TRUE(IFilesystem::create(fs).ok());

  tob::utils::UniqueFd fd_dir;
  ASSERT_TRUE(fs->open(fd_dir, "/proc/self/fd", O_DIRECTORY));

  auto fd_name = std::to_string(fd_dir.get());
  bool found = false;
  auto succeeded =
      fs->enumFiles(fd_dir.get(), [&](const std::string& name, bool directory) {
        if (name == fd_name && !directory) {
          found = true;
        }
      });

  EXPECT_TRUE(succeeded);
  EXPECT_TRUE(found);
  EXPECT_NE(fcntl(fd_dir.get(), F_GETFD), -1);
}

} // namespace osquery
