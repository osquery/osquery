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
#include <osquery/filesystem/linux/mounts.h>
#include <osquery/logger/logger.h>

#include <boost/algorithm/string.hpp>

namespace osquery {
namespace tables {
Status keyNameFromFilePath(std::string& key_name,
                           const std::string& selinuxfs_path,
                           const std::string& file_path);

Status translateBooleanKeyValue(std::string& value,
                                const std::string& raw_value);

namespace {
Status getSelinuxfsMountPath(std::string& path) {
  path = {};

  MountedFilesystems mounted_fs{};
  auto status = getMountedFilesystems(mounted_fs);
  if (!status.ok()) {
    return status;
  }

  // clang-format off
  auto selinuxfs_info_it = std::find_if(
    mounted_fs.begin(),
    mounted_fs.end(),

    [](const MountInformation &mount_info) -> bool {
      return (mount_info.type == "selinuxfs");
    }
  );
  // clang-format on

  if (selinuxfs_info_it != mounted_fs.end()) {
    path = selinuxfs_info_it->path;
  }

  return Status::success();
}

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
                        const std::string& selinuxfs_path,
                        const std::string& key) {
  row = {};

  row["scope"] = scope;
  row["key"] = key;

  auto path = selinuxfs_path + "/" + scope + "/" + key;

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

Status generateScope(QueryData& row_list,
                     const std::string& selinuxfs_path,
                     const std::string& scope) {
  auto scope_directory_path = selinuxfs_path + "/" + scope;

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
    status = keyNameFromFilePath(key_name, selinuxfs_path, path);
    if (!status.ok()) {
      LOG(ERROR) << "Invalid SELinux key path '" + path
                 << "'. Error: " << status.getMessage();
      continue;
    }

    Row row;
    status = generateScopeKey(row, scope, selinuxfs_path, key_name);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
      continue;
    }

    row_list.push_back(std::move(row));
  }

  return Status::success();
}

Status generateClasses(QueryData& row_list, const std::string& selinuxfs_path) {
  auto class_root_path = selinuxfs_path + "/class";

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
                           const std::string& selinuxfs_path,
                           const std::string& file_path) {
  // This limit only applies to this specific case and not to the
  // items in the 'class' scope
  static const std::size_t kMinimumPathSize = selinuxfs_path.size() + 2U;

  key_name = {};

  if (file_path.find(selinuxfs_path) != 0) {
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
  std::string selinuxfs_path;
  auto status = getSelinuxfsMountPath(selinuxfs_path);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to acquire the SELinux FS path"
               << status.getMessage();
    return {};
  }

  if (selinuxfs_path.empty()) {
    return {};
  }

  QueryData row_list;
  for (const auto& root_key : kRootKeyList) {
    Row row;
    status = generateScopeKey(row, "", selinuxfs_path, root_key);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to generate SELinux root key: "
                 << status.getMessage();
    }

    row_list.push_back(std::move(row));
  }

  for (const auto& scope : kScopeList) {
    status = generateScope(row_list, selinuxfs_path, scope);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to generate SELinux scope: " << status.getMessage();
    }
  }

  status = generateClasses(row_list, selinuxfs_path);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to generate SELinux class: " << status.getMessage();
  }

  return row_list;
}
} // namespace tables
} // namespace osquery
