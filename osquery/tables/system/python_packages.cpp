/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <stdlib.h>
#include <string>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

#ifdef WIN32
#include "windows/registry.h"
#endif

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

/// Number of fields when splitting metadata and info.
const size_t kNumFields = 2;
const std::set<std::string> kPythonPath = {
    "/usr/local/lib/python%/dist-packages",
    "/usr/local/lib/python%/site-packages",
    "/usr/local/lib64/python%/site-packages",
    "/opt/homebrew/lib/python%/dist-packages",
    "/opt/homebrew/lib/python%/site-packages",
    "/usr/lib/python%/dist-packages",
    "/usr/lib/python%/site-packages",
    "/Library/Python/%/site-packages",
};

// clang-format off
const std::set<std::string> kDarwinPythonPath = {
    "/System/Library/Frameworks/Python.framework/Versions",
    "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions",
};
// clang-format on

const std::set<std::string> kUserDirectoryPaths = {
    ".pyenv/versions",
    ".local/lib/python%",
};

const std::set<std::string> kDarwinUserDirectoryPaths = {
    "Library/Python",
};

const std::string kWinPythonInstallKey =
    "SOFTWARE\\Python\\PythonCore\\%\\InstallPath";

struct UserPath {
  enum class Type { Int64, String };

  Type type;
  std::int64_t intValue;
  std::string stringValue;

  UserPath(std::int64_t value) : type(Type::Int64), intValue(value) {}
  UserPath(std::string value)
      : type(Type::String), stringValue(std::move(value)) {}
};

void genPackage(const std::string& path, Row& r, Logger& logger) {
  std::string content;
  auto s = readFile(path, content);
  if (!s.ok()) {
    logger.log(google::GLOG_WARNING, s.getMessage());
    logger.vlog(1, "Cannot find info file: " + path);
    return;
  }

  auto lines = split(content, "\n");

  for (const auto& line : lines) {
    auto fields = split(line, ":");

    if (fields.size() != kNumFields) {
      continue;
    }

    if (fields[0] == "Name") {
      r["name"] = fields[1];
    } else if (fields[0] == "Version") {
      r["version"] = fields[1];
    } else if (fields[0] == "Summary") {
      r["summary"] = fields[1];
    } else if (fields[0] == "Author") {
      r["author"] = fields[1];
    } else if (fields[0] == "License") {
      r["license"] = fields[1];
      break;
    }
  }
}

void genSiteDirectories(const std::string& site,
                        QueryData& results,
                        Logger& logger,
                        const std::int64_t& user_id) {
  std::vector<std::string> directories;

  if (!listDirectoriesInDirectory(site, directories, true).ok()) {
    return;
  }

  for (const auto& directory : directories) {
    if (!isDirectory(directory).ok()) {
      continue;
    }

    Row r;
    if (boost::algorithm::ends_with(directory, ".dist-info")) {
      auto path = directory + "/METADATA";
      genPackage(path, r, logger);
    } else if (boost::algorithm::ends_with(directory, ".egg-info")) {
      auto path = directory + "/PKG-INFO";
      genPackage(path, r, logger);
    } else {
      continue;
    }

    r["directory"] = site;
    r["path"] = directory;
    r["pid_with_namespace"] = "0";
    r["uid"] = BIGINT(user_id);
    results.push_back(r);
  }
}

std::vector<std::string> listWinPythonPaths(const std::string& keyGlob) {
#ifdef WIN32
  std::vector<std::string> results;

  std::set<std::string> installPathKeys;
  auto status = expandRegistryGlobs(keyGlob, installPathKeys);
  if (!status.ok()) {
    return {};
  }

  QueryData pythonInstallLocation;
  for (const auto& installKey : installPathKeys) {
    queryKey(installKey, pythonInstallLocation);
    for (const auto& p : pythonInstallLocation) {
      if (p.at("name") != "(Default)") {
        continue;
      }
      results.push_back(p.at("data"));
    }
    pythonInstallLocation.clear();
  }
  return results;
#else
  return {};
#endif
}

std::vector<std::string> traverseVersions(const std::string& path) {
  std::vector<std::string> versions;
  if (!listDirectoriesInDirectory(path, versions, false).ok()) {
    return {};
  }

  std::vector<std::string> all_paths;
  for (const auto& version : versions) {
    auto version_path = fs::path(version);
    if (fs::is_symlink(symlink_status(version_path))) {
      continue;
    }

    auto path = version + "/lib/python%/site-packages";
    std::vector<std::string> sites;
    resolveFilePattern(path, sites);
    for (const auto& site : sites) {
      all_paths.push_back(site);
    }
  }

  return all_paths;
}

std::vector<std::map<std::string, UserPath>> getUserPathList(
    const QueryContext& context) {
  std::vector<std::map<std::string, UserPath>> paths_list;

  // `all` is set to true for windows to not break existing behavior.
  // Windows will always return all users' packages.
  auto user_list =
      usersFromContext(context, isPlatform(PlatformType::TYPE_WINDOWS));
  for (const auto& user : user_list) {
    if (user.count("uid") == 0 || user.count("directory") == 0) {
      continue;
    }

    const auto& uid_as_string = user.at("uid");
    auto uid_as_big_int = tryTo<int64_t>(uid_as_string, 10);
    if (uid_as_big_int.isError()) {
      LOG(ERROR) << "Invalid uid field returned: " << uid_as_string;
      continue;
    }
    const auto& path = user.at("directory");

    if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
      std::set<std::string> user_paths = kUserDirectoryPaths;

      if (isPlatform(PlatformType::TYPE_OSX)) {
        user_paths.insert(kDarwinUserDirectoryPaths.begin(),
                          kDarwinUserDirectoryPaths.end());
      }

      for (const auto& path_postfix : user_paths) {
        auto dir = path + "/" + path_postfix + "/";
        std::vector<std::string> site_paths;

        // check versioned pattern, nested
        // versions/%d.%d/lib/python%d.%d
        std::vector<std::string> versions = traverseVersions(dir);
        if (!versions.empty()) {
          site_paths.insert(site_paths.end(), versions.begin(), versions.end());
        } else {
          // check basic path, non-versioned
          // lib/python%d.%d
          std::vector<std::string> sites;
          resolveFilePattern(dir, sites);
          site_paths.insert(site_paths.end(), sites.begin(), sites.end());
        }

        for (const auto& site_path : site_paths) {
          std::map<std::string, UserPath> user_path;
          user_path = {
              {"user_id", uid_as_big_int.get()},
              {"path", site_path},
          };
          paths_list.push_back(user_path);
        }
      }
    }

    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      const auto& uuid_as_string = user.at("uuid");
      auto installPathKey =
          "HKEY_USERS\\" + uuid_as_string + "\\" + kWinPythonInstallKey;
      auto win_paths = listWinPythonPaths(installPathKey);

      for (const auto& win_path : win_paths) {
        std::map<std::string, UserPath> user_path;
        user_path = {
            {"user_id", uid_as_big_int.get()},
            {"path", win_path},
        };
        paths_list.push_back(user_path);
      }
    }
  }

  return paths_list;
}

QueryData genPythonPackagesImpl(QueryContext& context, Logger& logger) {
  QueryData results;
  std::set<std::string> paths;
  bool directory_filter = context.constraints.count("directory") > 0 &&
                          context.constraints.at("directory").exists(EQUALS);

  if (directory_filter) {
    paths = context.constraints["directory"].getAll(EQUALS);
  } else {
    for (const auto& path : kPythonPath) {
      std::vector<std::string> sites;
      resolveFilePattern(path, sites);
      for (const auto& site : sites) {
        paths.insert(site);
      }
    }
  }
  for (const auto& key : paths) {
    genSiteDirectories(key, results, logger, 0);
  }
  // If user has specified `where directory = "path"` then return results early.
  if (directory_filter) {
    return results;
  }

  // Enumerate user installed python packages
  auto user_paths = getUserPathList(context);
  for (const auto& user_path : user_paths) {
    genSiteDirectories(user_path.at("path").stringValue,
                       results,
                       logger,
                       user_path.at("user_id").intValue);
  }

  if (isPlatform(PlatformType::TYPE_OSX)) {
    for (const auto& dir : kDarwinPythonPath) {
      std::vector<std::string> versions = traverseVersions(dir);
      for (const auto& site_path : versions) {
        genSiteDirectories(site_path, results, logger, 0);
      }
    }
  } else if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    // Enumerate any system installed python packages
    auto installPathKey = "HKEY_LOCAL_MACHINE\\" + kWinPythonInstallKey;
    auto win_paths = listWinPythonPaths(installPathKey);

    for (const auto& win_path : win_paths) {
      genSiteDirectories(win_path, results, logger, 0);
    }
  }

  return results;
}

QueryData genPythonPackages(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(
        context, "python_packages", genPythonPackagesImpl);
  } else {
    GLOGLogger logger;
    return genPythonPackagesImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
