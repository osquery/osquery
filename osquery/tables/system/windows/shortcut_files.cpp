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
#include <osquery/utils/windows/shelllnk.h>

#include <boost/filesystem.hpp>

#include <iostream>
#include <string>
#include <sstream>
#include <fstream>


namespace osquery {
namespace tables {

QueryData genShortcutFiles(QueryContext& context) {
  QueryData results;
  const boost::filesystem::path lnk =
      "C:\\Users\\Public\\Desktop\\Visual Studio Code.lnk";
  std::ifstream read_lnk(lnk.string(), std::ios::out | std::ios::binary);
  if (!read_lnk) {
    std::cout << "Error!" << std::endl;
  }
  //LnkFile test;
  //rf.read(test, 20);
  std::vector<unsigned char> lnk_data((std::istreambuf_iterator<char>(read_lnk)), (std::istreambuf_iterator<char>()));
  read_lnk.close();
  //std::string str(test);
  //std::cout << test.header << std::endl;
  std::cout << lnk_data[0] << std::endl;
  std::stringstream ss;
  for (const auto& hex_char : lnk_data) {
    std::stringstream value;
    //std::cout << std::hex << (int)test << std::endl;
   value << std::hex << (int)(hex_char);
   // Add additional 0 if single hex value is 0-F to make it perfectly balance...
    if (value.str().size() == 1) {
      ss << "0";
    }
    ss << value.str(); // std::hex << (int)(hex_char);

  }
  const std::string lnk_hex = ss.str();
  std::cout << lnk_hex << std::endl;
  LinkFileHeader data;
  data = parseShortcutHeader(lnk_hex);
  return results;
}
} // namespace tables
} // namespace osquery