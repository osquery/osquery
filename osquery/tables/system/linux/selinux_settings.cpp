/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include <boost/algorithm/string.hpp>

namespace osquery {
namespace tables {
Status keyNameFromFilePath(std::string& key_name, const std::string& file_path);

Status translateBooleanKeyValue(std::string& value,
                                const std::string& raw_value);

namespace {
const std::string kSELinuxSysPath{"/sys/fs/selinux"};

const std::vector<std::string> kRootKeyList = {"checkreqprot",
                                               "deny_unknown",
                                               "enforce",
                                               "mls",
                                               "policyvers",
                                               "reject_unknown"};

const std::vector<std::string> kScopeList = {
    "booleans", "policy_capabilities", "initial_contexts"};

Status generateScopeKey(Row& row,
                        const std::string& scope,
                        const std::string& key,
                        const std::string& path) {
  row = {};

  row["scope"] = scope;
  row["key"] = key;

  std::string raw_value;
  auto status = readFile(path, raw_value);
  if (!status.ok()) {
    return Status::failure("Failed to retrieve SELinux key value: " + path +
                           ". Error: " + status.getMessage());
  }

  std::string value;
  if (scope == "booleans") {
    status = translateBooleanKeyValue(value, raw_value);
    if (!status.ok()) {
      return Status::failure("Failed to retrieve SELinux key value: " + path +
                             ". Error: " + status.getMessage());
    }

  } else {
    value = std::move(raw_value);
  }

  row["value"] = std::move(value);
  return Status::success();
}

Status generateScope(QueryData& row_list, const std::string& scope) {
  auto scope_directory_path = kSELinuxSysPath + "/" + scope;

  std::vector<std::string> path_list;
  auto status = listFilesInDirectory(scope_directory_path, path_list, true);
  if (!status.ok()) {
    return Status::failure("Failed to enumerate the files in '" +
                           scope_directory_path + "': " + status.getMessage());
  }

  for (const auto& path : path_list) {
    if (isDirectory(path).ok()) {
      continue;
    }

    std::string key_name = {};
    status = keyNameFromFilePath(key_name, path);
    if (!status.ok()) {
      LOG(ERROR) << "Invalid SELinux key path '" + path
                 << "'. Error: " << status.getMessage();
      continue;
    }

    Row row;
    status = generateScopeKey(row, scope, key_name, path);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
      continue;
    }

    row_list.push_back(std::move(row));
  }

  return Status::success();
}

Status generateClasses(QueryData& row_list) {
  auto class_root_path = kSELinuxSysPath + "/class";

  std::vector<std::string> path_list;
  auto status = listFilesInDirectory(class_root_path, path_list, true);
  if (!status.ok()) {
    return Status::failure(
        "Failed to enumerate the SELinux settings from under '" +
        class_root_path + "': " + status.getMessage());
  }

  for (const auto& path : path_list) {
    if (isDirectory(path).ok()) {
      continue;
    }

    auto value_index = path.find_last_of('/');
    if (value_index == std::string::npos) {
      continue;
    }

    ++value_index;
    if (value_index >= path.size()) {
      continue;
    }

    auto value = path.substr(value_index);
    if (value == "index") {
      continue;
    }

    auto key_index = class_root_path.size() + 1U;
    auto key_length = value_index - key_index - 1U;
    auto key = path.substr(key_index, key_length);

    Row row = {};
    row["scope"] = "class";
    row["key"] = key;
    row["value"] = value;

    row_list.push_back(std::move(row));
  }

  return Status::success();
}
} // namespace

Status keyNameFromFilePath(std::string& key_name,
                           const std::string& file_path) {
  // This limit only applies to this specific case and not to the
  // items in the 'class' scope
  static const std::size_t kMinimumPathSize = kSELinuxSysPath.size() + 2U;

  key_name = {};

  if (file_path.find(kSELinuxSysPath) != 0) {
    return Status::failure("The given path is outside the SELinux folder");
  }

  if (file_path.size() <= kMinimumPathSize) {
    return Status::failure("The given path is too small");
  }

  auto key_name_index = file_path.find_last_of('/');
  if (key_name_index == std::string::npos ||
      key_name_index + 1 >= file_path.size()) {
    return Status::failure("Invalid path specified");
  }

  ++key_name_index;

  key_name = file_path.substr(key_name_index);
  if (key_name.empty()) {
    return Status::failure("Key name is empty");
  }

  return Status::success();
}

Status translateBooleanKeyValue(std::string& value,
                                const std::string& raw_value) {
  value = {};

  if (raw_value == "0 0") {
    value = "off";

  } else if (raw_value == "1 1") {
    value = "on";

  } else {
    return Status::failure("Invalid raw value for boolean key");
  }

  return Status::success();
}

QueryData genSELinuxSettings(QueryContext& context) {
  QueryData row_list;

  for (const auto& root_key : kRootKeyList) {
    auto path = kSELinuxSysPath + "/" + root_key;

    if (!pathExists(path).ok()) {
      continue;
    }

    Row row;
    auto status = generateScopeKey(row, "", root_key, path);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to generate SELinux root key: "
                 << status.getMessage();
    }

    row_list.push_back(std::move(row));
  }

  for (const auto& scope : kScopeList) {
    auto status = generateScope(row_list, scope);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to generate SELinux scope: " << status.getMessage();
    }
  }

  auto status = generateClasses(row_list);
  if (!status.ok()) {
    LOG(ERROR) << "failed to bla bla";
  }

  return row_list;
}
} // namespace tables
} // namespace osquery
