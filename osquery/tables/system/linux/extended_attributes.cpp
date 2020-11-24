/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cctype>

#include <sys/capability.h>
#include <sys/xattr.h>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/filesystem/posix/xattrs.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/base64.h>

namespace osquery {
namespace tables {
namespace {
const std::string kSecurityCapabilityXattrName{"security.capability"};

std::set<std::string> getPathListFromConstraints(QueryContext& context) {
  auto path_list = context.constraints["path"].getAll(EQUALS);

  context.expandConstraints(
      "path",
      LIKE,
      path_list,
      [&](const std::string& pattern, std::set<std::string>& path_list) {
        std::vector<std::string> resolved_pattern_list;
        auto status = resolveFilePattern(
            pattern, resolved_pattern_list, GLOB_ALL | GLOB_NO_CANON);

        if (!status.ok()) {
          return status;
        }

        path_list.insert(std::make_move_iterator(resolved_pattern_list.begin()),
                         std::make_move_iterator(resolved_pattern_list.end()));

        return Status::success();
      });

  return path_list;
}

Status getCapabilities(std::string& capabilities, const std::string& path) {
  capabilities = {};

  auto cap = cap_get_file(path.c_str());
  if (cap == nullptr) {
    if (errno == ENODATA) {
      return Status::success();
    }

    return Status::failure(
        "Failed to acquire the capabilities for the following path: " + path);
  }

  auto buffer = cap_to_text(cap, nullptr);
  cap_free(cap);

  if (buffer != nullptr) {
    capabilities = buffer;
    cap_free(buffer);
  }

  return Status::success();
}
} // namespace

Status generateXattrRowsForPath(QueryData& output, const std::string& path) {
  ExtendedAttributeMap xattr_map;
  auto status = getExtendedAttributes(xattr_map, path);
  if (!status.ok()) {
    return status;
  }

  Row row = {};
  row["path"] = TEXT(path);

  auto path_obj = boost::filesystem::path(path);
  row["directory"] = TEXT(path_obj.parent_path().string());

  std::string capabilities = {};
  bool capabilities_found{false};

  status = getCapabilities(capabilities, path);
  if (status.ok()) {
    if (!capabilities.empty()) {
      row["key"] = TEXT(kSecurityCapabilityXattrName);
      row["value"] = TEXT(capabilities);
      row["base64"] = INTEGER(0);

      output.push_back(row);
    }

    capabilities_found = true;
  }

  for (const auto& p : xattr_map) {
    const auto& key_name = p.first;
    const auto& key_value = p.second;

    // Include the capabilities in raw form if we were not able to correctly
    // decode them
    if (key_name == kSecurityCapabilityXattrName && capabilities_found) {
      continue;
    }

    // Add empty values as base64
    if (key_value.empty()) {
      row["key"] = TEXT(key_name);
      row["value"] = TEXT("");
      row["base64"] = INTEGER("1");

      output.push_back(row);
      continue;
    }

    // Rules to mark values as printable:
    // 1. A null terminator must be present
    // 2. All characters up to the null terminator must be printable
    // 3. The null terminator must be located at the end of the value buffer
    auto char_it = std::find_if(key_value.begin(),
                                key_value.end(),

                                [](std::uint8_t byte) -> bool {
                                  auto as_integer = static_cast<int>(byte);
                                  return !std::isprint(as_integer);
                                });

    bool printable = false;
    if (char_it != key_value.end() &&
        std::next(char_it, 1) == key_value.end() && *char_it == 0) {
      printable = true;
    }

    auto value_size = key_value.size();
    if (printable) {
      --value_size;
    }

    auto value = std::string(value_size, 0);
    std::memcpy(&value[0], key_value.data(), value_size);

    if (!printable) {
      value = base64::encode(value);
    }

    row["key"] = TEXT(key_name);
    row["value"] = TEXT(value);
    row["base64"] = printable ? INTEGER(0) : INTEGER(1);

    output.push_back(row);
  }

  return Status::success();
}

QueryData genXattr(QueryContext& context) {
  QueryData output;

  auto path_list = getPathListFromConstraints(context);
  for (const auto& path : path_list) {
    auto status = generateXattrRowsForPath(output, path);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
    }
  }

  return output;
}
} // namespace tables
} // namespace osquery
