/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/shellitem.h>

#include <boost/filesystem.hpp>

#include <iostream>
#include <string>
#include <fstream>

struct LnkFile {
  char header[4];
  char guid[16];
};

namespace osquery {
namespace tables {

QueryData genShortcutFiles(QueryContext& context) {
  QueryData results;
  const boost::filesystem::path lnk =
      "C:\\Users\\Public\\Desktop\\Visual Studio Code.lnk";
  std::ifstream rf(lnk.string(), std::ios::out | std::ios::binary);
  if (!rf) {
    std::cout << "Error!" << std::endl;
  }
  LnkFile test;
  rf.read(test, 200);
  std::string str(test);
  std::cout << test.header << std::endl;
  return results;
}
} // namespace tables
} // namespace osquery