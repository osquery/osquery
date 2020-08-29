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

#include <boost/algorithm/string.hpp>

namespace osquery {
namespace tables {
namespace {
struct AppArmorProfile final {
  std::string path;
  std::string name;
  std::string attach;
  std::string mode;
  std::string sha1;
};

using AppArmorProfileList = std::vector<AppArmorProfile>;
using ProfilePathQueueEntry = std::pair<std::string, std::string>;
using ProfilePathQueue = std::vector<ProfilePathQueueEntry>;

const std::string kAppArmorProfilesPath{
    "/sys/kernel/security/apparmor/policy/profiles"};

Status generateProfile(AppArmorProfile& profile,
                       const std::string& profile_path,
                       const std::string& parent_name) {
  profile = {};

  auto status = readFile(profile_path + "/attach", profile.attach);
  if (!status.ok()) {
    return status;
  }

  boost::trim(profile.attach);

  status = readFile(profile_path + "/mode", profile.mode);
  if (!status.ok()) {
    return status;
  }

  boost::trim(profile.mode);

  status = readFile(profile_path + "/name", profile.name);
  if (!status.ok()) {
    return status;
  }

  boost::trim(profile.name);

  status = readFile(profile_path + "/sha1", profile.sha1);
  if (!status.ok()) {
    return status;
  }

  boost::trim(profile.sha1);

  profile.path = parent_name;
  if (!profile.path.empty()) {
    profile.path += "//";
  }

  profile.path += profile.name;
  return Status::success();
}

Status generateProfilePathQueue(ProfilePathQueue& queue,
                                const std::string& parent_name,
                                const std::string& path) {
  std::vector<std::string> path_list;

  auto status = listDirectoriesInDirectory(path, path_list, false);
  if (!status.ok()) {
    return status;
  }

  for (auto& p : path_list) {
    queue.push_back(std::make_pair(parent_name, std::move(p)));
  }

  return Status::success();
}

Status generateProfileList(AppArmorProfileList& profile_list) {
  profile_list = {};

  ProfilePathQueue profile_path_queue;

  auto status =
      generateProfilePathQueue(profile_path_queue, "", kAppArmorProfilesPath);

  if (!status.ok()) {
    return Status::failure("Failed to access AppArmor's \"profiles\" folder");
  }

  while (!profile_path_queue.empty()) {
    auto queue_entry = profile_path_queue.back();
    profile_path_queue.pop_back();

    const auto& parent_name = queue_entry.first;
    const auto& profile_path = queue_entry.second;

    if (!isDirectory(profile_path).ok()) {
      continue;
    }

    AppArmorProfile apparmor_profile;
    status = generateProfile(apparmor_profile, profile_path, parent_name);

    if (!status.ok()) {
      LOG(ERROR) << "Failed to open the following AppArmor profile: "
                 << profile_path << ". " << status.getMessage();

      continue;
    }

    auto subprofiles_folder = profile_path + "/profiles";
    if (pathExists(subprofiles_folder).ok()) {
      ProfilePathQueue additional_queue_items;

      status = generateProfilePathQueue(
          additional_queue_items, apparmor_profile.name, subprofiles_folder);

      if (!status.ok()) {
        LOG(ERROR) << "Failed to list the subprofiles of the following "
                      "AppArmor profile: "
                   << profile_path << ". " << status.getMessage();

        continue;
      }

      profile_path_queue.insert(
          profile_path_queue.end(),
          std::make_move_iterator(additional_queue_items.begin()),
          std::make_move_iterator(additional_queue_items.end()));
    }

    profile_list.push_back(std::move(apparmor_profile));
  }

  return Status::success();
}
} // namespace

QueryData genAppArmorProfiles(QueryContext& context) {
  if (!pathExists(kAppArmorProfilesPath).ok()) {
    return {};
  }

  AppArmorProfileList profile_list;
  auto status = generateProfileList(profile_list);
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    return {};
  }

  QueryData row_list;

  for (const auto& profile : profile_list) {
    Row row = {};
    row["name"] = profile.name;
    row["mode"] = profile.mode;
    row["attach"] = profile.attach;
    row["sha1"] = profile.sha1;
    row["path"] = profile.path;

    row_list.push_back(std::move(row));
  }

  return row_list;
}
} // namespace tables
} // namespace osquery
