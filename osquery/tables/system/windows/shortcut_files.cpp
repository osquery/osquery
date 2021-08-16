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
#include <osquery/tables/system/windows/shortcut_files.h>
#include <osquery/utils/conversions/join.h>

#include <osquery/logger/logger.h>
#include <osquery/utils/windows/shelllnk.h>

#include <boost/filesystem.hpp>

#include <sstream>
#include <string>

namespace osquery {
namespace tables {

LnkData parseShortcutFiles(const LinkFileHeader& data,
                           const std::string& short_data_string) {
  TargetInfo target_data;
  LocationInfo location_data;
  ExtraDataTracker extra_data;
  DataStringInfo data_info_string;
  std::string data_string = short_data_string;
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
  LnkData data_lnk;
  data_lnk.header = data;
  data_lnk.target_data = target_data;
  data_lnk.location_data = location_data;
  data_lnk.extra_data = extra_data;
  data_lnk.data_info_string = data_info_string;
  data_lnk.target_path = target_path;
  return data_lnk;
}

void buildLnkTable(QueryData& results, LnkData data, std::string& path) {
  Row r;
  r["path"] = path;
  r["target_created"] = INTEGER(data.header.creation_time);
  r["target_modified"] = INTEGER(data.header.modified_time);
  r["target_accessed"] = INTEGER(data.header.access_time);
  r["target_size"] = BIGINT(data.header.file_size);

  if (data.header.flags.has_target_id_list) {
    r["target_path"] = data.target_path;
    if (data.target_data.mft_entry != -1LL) {
      r["mft_entry"] = BIGINT(data.target_data.mft_entry);
      r["mft_sequence"] = INTEGER(data.target_data.mft_sequence);
    }
  }
  if (data.header.flags.has_link_info) {
    r["local_path"] = data.location_data.local_path;
    r["common_path"] = data.location_data.common_path;
    r["device_type"] = data.location_data.type;
    r["volume_serial"] = data.location_data.serial;
    r["share_name"] = data.location_data.share_name;
  }
  if (data.header.flags.has_name || data.header.flags.has_relative_path ||
      data.header.flags.has_working_dir || data.header.flags.has_arguments ||
      data.header.flags.has_icon_location) {
    r["relative_path"] = data.data_info_string.relative_path;
    r["command_args"] = data.data_info_string.arguments;
    r["icon_path"] = data.data_info_string.icon_location;
    r["working_path"] = data.data_info_string.working_path;
    r["description"] = data.data_info_string.description;
  }
  r["hostname"] = data.extra_data.hostname;
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
    LnkData data_lnk;
    data_lnk = parseShortcutFiles(data, data_string);
    buildLnkTable(results, data_lnk, lnk_path);
  }
  return results;
}
} // namespace tables
} // namespace osquery