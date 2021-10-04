/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <iostream>
#include <osquery/utils/sleuthkit/sleuthkit.h>
#include <osquery/utils/system/env.h>
#include <string>
#include <vector>
namespace osquery {
class SleuthkitTests : public testing::Test {};

TEST_F(SleuthkitTests, test_read_file) {
  std::string drive_path = "\\\\.\\PhysicalDrive1";
  auto test = getEnvVar("TEST_CONF_FILES_DIR");
  if (!test.is_initialized()) {
    FAIL();
  }
  auto const test_filepath =
      boost::filesystem::path(*test + "/windows/sleuthkit/A file.txt")
          .make_preferred()
          .string();
  SleuthkitHelper dh(drive_path);
  std::vector<char> file_contents;

  dh.partitionsMinOsSize(
      ([&dh, &test_filepath, &file_contents](const TskVsPartInfo* part) {
        if (part->getFlags() != TSK_VS_PART_FLAG_ALLOC) {
          return;
        }

        std::string address = std::to_string(part->getAddr());
        std::unique_ptr<TskFsInfo> fs(new TskFsInfo);
        TSK_OFF_T offset = 0;
        auto status = fs->open(part, TSK_FS_TYPE_DETECT);
        // Cannot retrieve file information without accessing the filesystem.
        if (status) {
          // delete fs;
          return;
        }
        dh.readFile(address, fs, test_filepath, file_contents);
        if (file_contents.size() > 0) {
          return;
        }
      }));
  if (file_contents.empty()) {
    drive_path = "\\\\.\\PhysicalDrive0";
  }
  dh.partitionsMinOsSize(
      ([&dh, &test_filepath, &file_contents](const TskVsPartInfo* part) {
        if (part->getFlags() != TSK_VS_PART_FLAG_ALLOC) {
          return;
        }

        std::string address = std::to_string(part->getAddr());
        std::unique_ptr<TskFsInfo> fs(new TskFsInfo);
        TSK_OFF_T offset = 0;
        auto status = fs->open(part, TSK_FS_TYPE_DETECT);
        // Cannot retrieve file information without accessing the filesystem.
        if (status) {
          // delete fs;
          return;
        }
        dh.readFile(address, fs, test_filepath, file_contents);
        if (file_contents.size() > 0) {
          return;
        }
      }));
  std::cout << file_contents.size() << std::endl;
  std::string file_string(file_contents.begin(), file_contents.end());
  std::cout << file_string << std::endl;
  FAIL();
}

} // namespace osquery