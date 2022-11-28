/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/filesystem/filesystem.h>
#include <osquery/filesystem/mock_file_structure.h>

#include <boost/filesystem/path.hpp>

namespace osquery {

const std::string kTopLevelMockFolderName{"辞書"};

namespace fs = boost::filesystem;

fs::path createMockFileStructure() {
  const auto root_dir =
      fs::temp_directory_path() /
      fs::unique_path("osquery.tests.%%%%.%%%%");
  fs::create_directories(root_dir / kTopLevelMockFolderName / "/");
  fs::create_directories(root_dir / kTopLevelMockFolderName / "secondlevel1");
  fs::create_directories(root_dir / kTopLevelMockFolderName / "secondlevel2");
  fs::create_directories(root_dir / kTopLevelMockFolderName / "secondlevel3");
  fs::create_directories(root_dir / kTopLevelMockFolderName /
                         "secondlevel3/thirdlevel1");
  fs::create_directories(root_dir / "deep11/deep2/deep3/");
  fs::create_directories(root_dir / "deep1/deep2/");
  writeTextFile(root_dir / "root.txt", "root");
  writeTextFile(root_dir / "door.txt", "toor", 0550);
  writeTextFile(root_dir / "roto.txt", "roto");
  writeTextFile(root_dir / "deep1/level1.txt", "l1");
  writeTextFile(root_dir / "deep11/not_bash", "l1");
  writeTextFile(root_dir / "deep1/deep2/level2.txt", "l2");

  writeTextFile(root_dir / "deep11/level1.txt", "l1");
  writeTextFile(root_dir / "deep11/deep2/level2.txt", "l2");
  writeTextFile(root_dir / "deep11/deep2/deep3/level3.txt", "l3");

#ifdef WIN32
  writeTextFile(root_dir / "root2.txt", "l1");
#else
  boost::system::error_code ec;
  fs::create_symlink(
      root_dir / "root.txt", root_dir / "root2.txt", ec);
#endif
  return root_dir;
}

} // namespace osquery
