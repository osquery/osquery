/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/base64.h"
#include "osquery/core/conversions.h"
#include "osquery/tables/system/posix/xattr_utils.h"

#include <osquery/tables.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace {
Status appendDirectoryEntryAttributes(QueryData& results,
                                      const std::string& path) {
  ExtendedAttributes attributes;
  if (!getExtendedAttributes(attributes, path)) {
    return Status(1, "Failed to acquire the extended attributes for the following path: " + path);
  }

  for (const auto& p : attributes) {
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
