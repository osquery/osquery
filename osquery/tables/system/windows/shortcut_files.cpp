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

#include <boost/filesystem.hpp>

#include <sstream>
#include <string>

namespace osquery {
namespace tables {

void parseShortcutFiles(QueryData& results,
                        LinkFileHeader& data,
                        std::string& data_string,
                        std::string& lnk) {
  TargetInfo target_data;
  LocationInfo location_data;
  ExtraDataTracker extra_data;
  DataStringInfo data_info_string;
  if (data.flags.has_target_id_list) {
    target_data = parseTargetInfo(data_string);
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
  // Lookup and combine GUIDs and target file path
  if (!target_data.root_folder.empty()) {
    std::string guid_name;
    std::vector<std::string> full_path;
    // Check for GUID name if osquery fails to find it, fallback to the GUID
    auto status = getClassName('{' + target_data.root_folder + '}', guid_name);
    if (status.ok()) {
      full_path.push_back(guid_name);
    } else {
      full_path.push_back('{' + target_data.root_folder + '}');
    }
    // If Control Panel items were found lookup GUIDs and build path
    if (!target_data.control_panel.empty() ||
        !target_data.control_panel_category.empty()) {
      std::string guid_name;
      full_path.push_back(target_data.control_panel_category);
      status = getClassName('{' + target_data.control_panel + '}', guid_name);
      if (status.ok()) {
        full_path.push_back(guid_name);
      } else {
        full_path.push_back('{' + target_data.control_panel + '}');
      }

      target_path = osquery::join(full_path, "\\");
    } else {
      if (!target_data.path.empty()) {
        // Check if path is only a volume
        if (target_data.path.size() == 2 && target_data.path.back() == ':') {
          target_data.path = target_data.path + "\\";
        } else {
          full_path.push_back(target_data.path);
        }
      }
      target_path = osquery::join(full_path, "\\");
    }
  } else if (!target_data.property_guid.empty()) {
    // Lookup up GUID name for User Property Views
    std::string guid_name;
    std::vector<std::string> full_path;
    auto status =
        getClassName('{' + target_data.property_guid + '}', guid_name);
    if (status.ok()) {
      full_path.push_back(guid_name);
    } else {
      full_path.push_back('{' + target_data.property_guid + '}');
    }
    target_path = osquery::join(full_path, "\\");
  } else {
    // Check if path is only a volume
    if (target_data.path.size() == 2 && target_data.path.back() == ':') {
      target_data.path = target_data.path + "\\";
    }
    target_path = target_data.path;
  }
  Row r;
  r["path"] = lnk;
  r["target_created"] = INTEGER(data.creation_time);
  r["target_modified"] = INTEGER(data.modified_time);
  r["target_accessed"] = INTEGER(data.access_time);
  r["target_size"] = BIGINT(data.file_size);

  if (data.flags.has_target_id_list) {
    r["target_path"] = target_path;
    if (target_data.mft_entry != -1LL) {
      r["mft_entry"] = BIGINT(target_data.mft_entry);
      r["mft_sequence"] = INTEGER(target_data.mft_sequence);
    }
  }
  if (data.flags.has_link_info) {
    r["local_path"] = location_data.local_path;
    r["common_path"] = location_data.common_path;
    r["device_type"] = location_data.type;
    r["volume_serial"] = location_data.serial;
    r["share_name"] = location_data.share_name;
  }
  if (data.flags.has_name || data.flags.has_relative_path ||
      data.flags.has_working_dir || data.flags.has_arguments ||
      data.flags.has_icon_location) {
    r["relative_path"] = data_info_string.relative_path;
    r["command_args"] = data_info_string.arguments;
    r["icon_path"] = data_info_string.icon_location;
    r["working_path"] = data_info_string.working_path;
    r["description"] = data_info_string.description;
  }
  r["hostname"] = extra_data.hostname;
  results.push_back(r);
}

QueryData genShortcutFiles(QueryContext& context) {
  QueryData results;
  auto paths = context.constraints["path"].getAll(EQUALS);
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
    boost::filesystem::path path = lnk;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    std::string lnk_content;
    if (!readFile(path, lnk_content, 20).ok()) {
      VLOG(1) << "Failed to read shortcut file: " << lnk;
      continue;
    }
    std::stringstream check_ss;
    for (const auto& hex_char : lnk_content) {
      std::stringstream value;
      value << std::setfill('0') << std::setw(2);
      value << std::hex << std::uppercase << (int)(unsigned char)(hex_char);
      check_ss << value.str();
    }
    std::string header_sig = check_ss.str();

    // Check for shortcut header size (0x0000004c) and GUID
    // (00021401-0000-0000-c000-000000000046)
    if (header_sig != "4C0000000114020000000000C000000000000046") {
      continue;
    }

    // Read the whole shortcut file
    lnk_content = "";
    if (!readFile(path, lnk_content).ok()) {
      LOG(WARNING) << "Failed to read shortcut file: " << lnk;
      continue;
    }
    std::stringstream ss;
    for (const auto& hex_char : lnk_content) {
      std::stringstream value;
      value << std::setfill('0') << std::setw(2);
      value << std::hex << std::uppercase << (int)(unsigned char)(hex_char);
      ss << value.str();
    }

    const std::string lnk_hex = ss.str();
    LinkFileHeader data;

    data = parseShortcutHeader(lnk_hex);
    if (data.header.empty()) {
      continue;
    }
    const int lnk_data = 152;
    std::string data_string = lnk_hex.substr(lnk_data);
    std::string lnk_path = lnk;
    parseShortcutFiles(results, data, data_string, lnk_path);
  }
  return results;
}
} // namespace tables
} // namespace osquery