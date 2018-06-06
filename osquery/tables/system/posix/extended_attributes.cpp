/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <sys/xattr.h>

#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/base64.h"
#include "osquery/core/conversions.h"
#include "osquery/tables/system/posix/extended_attributes.h"

namespace fs = boost::filesystem;

namespace osquery {
namespace {
Status getExtendedAttribute(std::string& value,
                            const std::string& path,
                            const std::string& attribute_name) {
  value.clear();

  errno = 0;
  auto buffer_length =
      getxattr(path.c_str(), attribute_name.c_str(), nullptr, 0U);
  if (buffer_length == -1) {
    return Status(1, "Failed to determine the extended attribute size");
  }

  value.resize(buffer_length);
  if (getxattr(
          path.c_str(), attribute_name.c_str(), &value[0], buffer_length) !=
      buffer_length) {
    return Status(1, "Failed to retrieve the extended attribute value");
  }

  return Status(0, "OK");
}

Status getExtendedAttributeList(std::vector<std::string>& attribute_list,
                                const std::string& path) {
  attribute_list = {};

  auto buffer_length = listxattr(path.c_str(), nullptr, 0U);
  if (buffer_length == -1) {
    return Status(1, "Failed to determine the attribute list size");
  }

  std::string raw_attribute_list;
  raw_attribute_list.resize(buffer_length);
  if (listxattr(path.c_str(), &raw_attribute_list[0], buffer_length) !=
      buffer_length) {
    return Status(1, "Failed to retrieve the attribute list");
  }

  size_t attribute_name_start = 0U;

  for (size_t i = 0U; i < raw_attribute_list.size(); i++) {
    if (raw_attribute_list[i] == 0) {
      auto name_length = i - attribute_name_start;
      auto name = raw_attribute_list.substr(attribute_name_start, name_length);

      attribute_list.push_back(name);
      attribute_name_start = i + 1;
    }
  }

  return Status(0, "OK");
}

Status appendDirectoryEntryAttributes(QueryData& results,
                                      const std::string& path) {
  ExtendedAttributeList attribute_list;
  auto status = getAllExtendedAttributes(attribute_list, path);
  if (!status) {
    return status;
  }

  for (const auto& p : attribute_list) {
    const auto& name = p.first;
    const auto& value = p.second;

    std::string parent_path;
    try {
      parent_path = boost::filesystem::path(path).parent_path().string();
    } catch (...) {
      VLOG(1) << "Failed to determine the parent path for directory entry "
              << path;
    }

    Row r;
    r["path"] = path;
    r["directory"] = parent_path;
    r["key"] = name;

    auto value_printable = isPrintable(value);
    r["value"] = (value_printable) ? value : base64::encode(value);
    r["base64"] = (value_printable) ? INTEGER(0) : INTEGER(1);

    results.push_back(r);
  }

  return Status(0, "OK");
}
} // namespace

Status getAllExtendedAttributes(ExtendedAttributeList& attributes,
                                const std::string& path) {
  attributes = {};

  std::vector<std::string> attribute_list;
  auto status = getExtendedAttributeList(attribute_list, path);
  if (!status.ok()) {
    return status;
  }

  bool error_occurred = false;

  for (const auto& attribute_name : attribute_list) {
    std::string attribute_value;
    status = getExtendedAttribute(attribute_value, path, attribute_name);
    if (!status.ok()) {
      error_occurred = true;
      continue;
    }

    if (isSpecialExtendedAttribute(attribute_name)) {
      ExtendedAttributeList expanded_attributes;
      status = expandSpecialExtendedAttribute(
          expanded_attributes, path, attribute_name);
      if (status.ok()) {
        attributes.insert(attributes.end(),
                          expanded_attributes.begin(),
                          expanded_attributes.end());
      } else {
        VLOG(1) << status.getMessage();
      }

    } else {
      attributes.push_back(std::make_pair(attribute_name, attribute_value));
    }
  }

  if (error_occurred) {
    VLOG(1) << "One or more attributes could not be successfully retrieved "
               "from the following file: "
            << path
            << ". Note that the file may have been changed while the "
               "attributes were being enumerated";

    if (attributes.empty()) {
      return Status(1,
                    "Failed to retrieve the extended attributes from the file");
    }
  }

  return Status(0, "OK");
}

namespace tables {
QueryData genXattr(QueryContext& context) {
  QueryData results;

  // Resolve file paths for EQUALS and LIKE operations.
  auto paths = context.constraints["path"].getAll(EQUALS);
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

  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;

    // Folders can have extended attributes too
    boost::system::error_code ec;
    if (!(boost::filesystem::is_regular_file(path, ec) ||
          boost::filesystem::is_directory(path, ec))) {
      continue;
    }

    auto status = appendDirectoryEntryAttributes(results, path.string());
    if (!status.ok()) {
      VLOG(1) << status.getMessage();
    }
  }

  // Resolve directories for EQUALS and LIKE operations.
  auto directory_list = context.constraints["directory"].getAll(EQUALS);
  context.expandConstraints(
      "directory",
      LIKE,
      directory_list,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_FOLDERS | GLOB_NO_CANON);

        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  // Now loop through constraints using the directory column constraint.
  for (const auto& folder_path : directory_list) {
    if (!isReadable(folder_path) || !isDirectory(folder_path)) {
      continue;
    }

    std::vector<std::string> directory_entries;
    if (listFilesInDirectory(folder_path, directory_entries).ok()) {
      for (const auto& path : directory_entries) {
        auto status = appendDirectoryEntryAttributes(results, path);
        if (!status.ok()) {
          VLOG(1) << status.getMessage();
        }
      }
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
