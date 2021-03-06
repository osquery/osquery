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
#include <osquery/tables/system/windows/registry.h>
#include <osquery/utils/conversions/join.h>

#include <osquery/logger/logger.h>
#include <osquery/utils/windows/shelllnk.h>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace osquery {
namespace tables {

QueryData genShortcutFiles(QueryContext& context) {
  QueryData results;
  auto paths = context.constraints["path"].getAll(EQUALS);
  Row r;
  // Expand contraints
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  boost::system::error_code ec;
  for (const auto& lnk : paths) {
    std::cout << lnk << std::endl;
    boost::filesystem::path path = lnk;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    std::ifstream check_lnk(lnk, std::ios::out | std::ios::binary);
    if (!check_lnk) {
      LOG(WARNING) << "Failed to read header: " << lnk;
    }
    char check_data[20];
    check_lnk.read(check_data, 20);
    check_lnk.close();

    std::stringstream check_ss;
    for (const auto& hex_char : check_data) {
      std::stringstream value;
      value << std::hex << std::uppercase << (int)(hex_char);
      // Add additional 0 if single hex value is 0-F
      if (value.str().size() == 1) {
        check_ss << "0";
      }
      check_ss << value.str();
    }
    std::string header_sig = check_ss.str();

    // remove signed extension characters
    boost::erase_all(header_sig, "FFFFFF");

    // Check for shortcut header size (0x0000004c) and GUID
    // (00021401-0000-0000-c000-000000000046)
    if (header_sig != "4C0000000114020000000000C000000000000046") {
      continue;
    }

    // Read the whole shortcut file
    std::ifstream read_lnk(lnk, std::ios::out | std::ios::binary);
    if (!read_lnk) {
      LOG(WARNING) << "Failed to read file: " << lnk;
    }

    std::vector<unsigned char> lnk_data(
        (std::istreambuf_iterator<char>(read_lnk)),
        (std::istreambuf_iterator<char>()));
    read_lnk.close();
    std::stringstream ss;
    for (const auto& hex_char : lnk_data) {
      std::stringstream value;
      value << std::hex << std::uppercase << (int)(hex_char);
      // Add additional 0 if single hex value is 0-F
      if (value.str().size() == 1) {
        ss << "0";
      }
      ss << value.str();
    }
    const std::string lnk_hex = ss.str();
    LinkFileHeader data;
    TargetInfo target_data;
    LocationInfo location_data;
    ExtraDataTracker extra_data;
    DataStringInfo data_info_string;

    data = parseShortcutHeader(lnk_hex);
    if (data.header == "") {
      continue;
    }
    std::string data_string = lnk_hex.substr(156);
    if (data.flags.has_target_id_list) {
      target_data = parseTargetInfo(lnk_hex.substr(156));
      data_string = target_data.data;
    }
    if (data.flags.has_link_info) {
      location_data = parseLocationData(data_string);
      data_string = location_data.data;
    }
    if (data.flags.has_name || data.flags.has_relative_path ||
        data.flags.has_working_dir || data.flags.has_arguments ||
        data.flags.has_icon_location) {
      data_info_string = parseDataString(data_string,
                                         data.flags.is_unicode,
                                         data.flags.has_name,
                                         data.flags.has_relative_path,
                                         data.flags.has_working_dir,
                                         data.flags.has_icon_location,
                                         data.flags.has_arguments);
      data_string = data_info_string.data;
    }
    extra_data = parseExtraDataTracker(data_string);

    std::string target_path = "";
    if (target_data.root_folder != "") {
      std::string guid_name;
      std::vector<std::string> full_path;
      auto status =
          getClassName("{" + target_data.root_folder + "}", guid_name);
      if (status.ok()) {
        full_path.push_back(guid_name);
      } else {
        full_path.push_back("{" + target_data.root_folder + "}");
      }
      full_path.push_back(target_data.path);
      target_path = osquery::join(full_path, "\\");
    } else {
      target_path = target_data.path;
    }

    r["path"] = lnk;
    r["target_path"] = target_path;
    r["local_path"] = location_data.local_path;
    r["common_path"] = location_data.common_path;
    r["target_created"] = INTEGER(data.creation_time);
    r["target_modified"] = INTEGER(data.modified_time);
    r["target_accessed"] = INTEGER(data.access_time);
    r["target_size"] = BIGINT(data.file_size);
    r["relative_directory"] = data_info_string.relative_path;
    r["command_args"] = data_info_string.arguments;
    r["hostname"] = extra_data.hostname;
    r["device_type"] = location_data.type;
    r["volume_serial"] = location_data.serial;
    r["share_name"] = location_data.share_name;
    r["mft_entry"] = BIGINT(target_data.mft_entry);
    r["mft_sequence"] = INTEGER(target_data.mft_sequence);
    results.push_back(r);
  }
  return results;
}
} // namespace tables
} // namespace osquery