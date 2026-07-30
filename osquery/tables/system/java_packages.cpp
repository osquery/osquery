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

#include <algorithm>
#include <sstream>
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
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#ifdef WIN32
#include "windows/registry.h"
#endif

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

/// Number of fields when splitting metadata and info.
const size_t kNumFields = 2;
const std::set<std::string> kJavaPath = {
    "/Library/Java/Extensions",
};

const std::set<std::string> kUserDirectoryPaths = {
    // Maven local repository
    ".m2/repository",
    // Gradle caches
    ".gradle/caches/modules-2/files-2.1",
};

const std::set<std::string> kDarwinUserDirectoryPaths = {
    // Maven local repository (macOS)
    ".m2/repository",
    // Gradle caches (macOS)
    ".gradle/caches/modules-2/files-2.1",
};

const std::string kWinJavaInstallKey =
    "SOFTWARE\\Java\\JavaCore\\%\\InstallPath";

struct UserPath {
  enum class Type { Int64, String };

  Type type;
  std::int64_t intValue;
  std::string stringValue;

  UserPath(std::int64_t value) : type(Type::Int64), intValue(value) {}
  UserPath(std::string value)
      : type(Type::String), stringValue(std::move(value)) {}
};

std::string extractAuthorFromPom(const std::string& content) {
  try {
    // Parse the XML content into a property tree
    boost::property_tree::ptree pt;
    std::istringstream stream(content);
    boost::property_tree::read_xml(stream, pt);

    std::string fallbackAuthor;

    // Navigate to the developers section
    auto developers = pt.get_child_optional("project.developers");
    if (!developers) {
      return "";
    }

    // Iterate through all developer nodes
    for (const auto& devPair : *developers) {
      if (devPair.first != "developer") {
        continue;
      }

      const auto& developer = devPair.second;

      // Get the developer's name as fallback
      if (fallbackAuthor.empty()) {
        fallbackAuthor = developer.get<std::string>("name", "");
      }

      // Check if this developer has the "owner" role
      auto roles = developer.get_child_optional("roles");
      if (roles) {
        bool hasOwnerRole = false;
        for (const auto& rolePair : *roles) {
          if (rolePair.first != "role") {
            continue;
          }

          std::string roleValue = rolePair.second.get_value<std::string>("");
          roleValue = boost::algorithm::to_lower_copy(
              boost::algorithm::trim_copy(roleValue));

          if (roleValue == "owner") {
            hasOwnerRole = true;
            break;
          }
        }

        // If this developer is the owner, return their email or name
        if (hasOwnerRole) {
          std::string ownerEmail = developer.get<std::string>("email", "");
          if (!ownerEmail.empty()) {
            return ownerEmail;
          }

          std::string ownerName = developer.get<std::string>("name", "");
          if (!ownerName.empty()) {
            return ownerName;
          }
        }
      }
    }

    return fallbackAuthor;
  } catch (const boost::property_tree::xml_parser_error& e) {
    // Failed to parse XML, return empty string
    return "";
  } catch (const std::exception& e) {
    // Other errors, return empty string
    return "";
  }
}

void genMavenPackage(const std::string& versionPath,
                     const std::string& groupId,
                     const std::string& artifactId,
                     const std::string& version,
                     Row& r,
                     Logger& logger) {
  // Maven repository structure: groupId/artifactId/version/
  r["name"] = groupId + ":" + artifactId;
  r["version"] = version;
  r["type"] = "Maven";

  // Try to find and parse POM file for additional metadata
  auto pomPath = versionPath + "/" + artifactId + "-" + version + ".pom";

  std::string content;
  auto s = readFile(pomPath, content);
  if (s.ok()) {
    // Extract basic info from POM (simplified parsing)
    // In a real implementation, you'd use an XML parser
    size_t descStart = content.find("<description>");
    size_t descEnd = content.find("</description>");
    if (descStart != std::string::npos && descEnd != std::string::npos) {
      descStart += 13; // length of "<description>"
      r["summary"] = content.substr(descStart, descEnd - descStart);
    }

    size_t licenseStart = content.find("<name>", content.find("<license>"));
    size_t licenseEnd = content.find("</name>", licenseStart);
    if (licenseStart != std::string::npos && licenseEnd != std::string::npos) {
      licenseStart += 6; // length of "<name>"
      r["license"] = content.substr(licenseStart, licenseEnd - licenseStart);
    }

    // Extract author from developers block
    std::string author = extractAuthorFromPom(content);
    if (!author.empty()) {
      r["author"] = author;
    }
  }
}

std::string getMavenGroupId(const std::string& repoPath,
                            const std::string& groupPath) {
  auto relativePath = groupPath;

  if (groupPath.compare(0, repoPath.size(), repoPath) == 0) {
    relativePath = groupPath.substr(repoPath.size());
  }

  boost::algorithm::trim_if(relativePath, boost::is_any_of("/\\"));
  if (relativePath.empty()) {
    return "";
  }

  std::replace(relativePath.begin(), relativePath.end(), '/', '.');
  std::replace(relativePath.begin(), relativePath.end(), '\\', '.');
  return relativePath;
}

void genMavenArtifactsRecursive(const std::string& repoPath,
                                const std::string& currentPath,
                                QueryData& results,
                                Logger& logger,
                                const std::int64_t& user_id) {
  std::vector<std::string> childDirs;
  if (!listDirectoriesInDirectory(currentPath, childDirs, false).ok()) {
    return;
  }

  for (const auto& childDir : childDirs) {
    if (!isDirectory(childDir).ok()) {
      continue;
    }

    const auto artifactId = fs::path(currentPath).filename().string();
    const auto version = fs::path(childDir).filename().string();
    const auto pomPath = childDir + "/" + artifactId + "-" + version + ".pom";

    // If a directory contains artifactId-version.pom, treat it as a version
    // directory under groupId/artifactId/version.
    if (pathExists(pomPath).ok()) {
      Row r;
      const auto groupPath = fs::path(currentPath).parent_path().string();
      const auto groupId = getMavenGroupId(repoPath, groupPath);

      genMavenPackage(childDir, groupId, artifactId, version, r, logger);

      r["directory"] = repoPath;
      r["path"] = childDir;
      r["pid_with_namespace"] = "0";
      r["uid"] = BIGINT(user_id);
      results.push_back(r);
    }

    genMavenArtifactsRecursive(repoPath, childDir, results, logger, user_id);
  }
}

void genGradlePackage(const std::string& versionPath,
                      const std::string& groupId,
                      const std::string& artifactId,
                      const std::string& version,
                      Row& r,
                      Logger& logger) {
  // Gradle cache structure: groupId/artifactId/version/hash/
  r["name"] = groupId + ":" + artifactId;
  r["version"] = version;
  r["type"] = "Gradle";

  // Look for POM file in hash subdirectories to extract metadata
  std::vector<std::string> hashDirs;
  if (listDirectoriesInDirectory(versionPath, hashDirs, false).ok()) {
    for (const auto& hashDir : hashDirs) {
      std::vector<std::string> files;
      if (listFilesInDirectory(hashDir, files, false).ok()) {
        for (const auto& file : files) {
          if (boost::algorithm::ends_with(file, ".pom")) {
            // Found POM file, parse it for metadata
            std::string content;
            auto s = readFile(file, content);
            if (s.ok()) {
              // Extract description
              size_t descStart = content.find("<description>");
              size_t descEnd = content.find("</description>");
              if (descStart != std::string::npos &&
                  descEnd != std::string::npos) {
                descStart += 13;
                r["summary"] = content.substr(descStart, descEnd - descStart);
              } else {
                r["summary"] = groupId + ":" + artifactId;
              }

              // Extract license
              size_t licenseStart =
                  content.find("<name>", content.find("<license>"));
              size_t licenseEnd = content.find("</name>", licenseStart);
              if (licenseStart != std::string::npos &&
                  licenseEnd != std::string::npos) {
                licenseStart += 6;
                r["license"] =
                    content.substr(licenseStart, licenseEnd - licenseStart);
              }

              // Extract author from developers block
              std::string author = extractAuthorFromPom(content);
              if (!author.empty()) {
                r["author"] = author;
              }
            }
            // Only parse the first POM found
            return;
          }
        }
      }
    }
  }

  // Fallback if no POM found
  r["summary"] = groupId + ":" + artifactId;
}

void genJavaPackage(const std::string& path, Row& r, Logger& logger) {
  std::string content;
  auto s = readFile(path, content);
  if (!s.ok()) {
    logger.log(google::GLOG_WARNING, s.getMessage());
    logger.log(1, "Cannot find info file: " + path);
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

void genMavenArtifacts(const std::string& repoPath,
                       QueryData& results,
                       Logger& logger,
                       const std::int64_t& user_id) {
  if (!isDirectory(repoPath).ok()) {
    return;
  }

  genMavenArtifactsRecursive(repoPath, repoPath, results, logger, user_id);
}

void genGradleArtifacts(const std::string& cachePath,
                        QueryData& results,
                        Logger& logger,
                        const std::int64_t& user_id) {
  // Gradle cache structure: groupId/artifactId/version/hash/
  std::vector<std::string> groupDirs;

  if (!listDirectoriesInDirectory(cachePath, groupDirs, false).ok()) {
    return;
  }

  for (const auto& groupDir : groupDirs) {
    if (!isDirectory(groupDir).ok()) {
      continue;
    }

    std::vector<std::string> artifactDirs;
    if (!listDirectoriesInDirectory(groupDir, artifactDirs, false).ok()) {
      continue;
    }

    for (const auto& artifactDir : artifactDirs) {
      if (!isDirectory(artifactDir).ok()) {
        continue;
      }

      std::vector<std::string> versionDirs;
      if (!listDirectoriesInDirectory(artifactDir, versionDirs, false).ok()) {
        continue;
      }

      for (const auto& versionDir : versionDirs) {
        if (!isDirectory(versionDir).ok()) {
          continue;
        }

        Row r;
        auto groupId = fs::path(groupDir).filename().string();
        auto artifactId = fs::path(artifactDir).filename().string();
        auto version = fs::path(versionDir).filename().string();

        genGradlePackage(versionDir, groupId, artifactId, version, r, logger);

        r["directory"] = cachePath;
        r["path"] = versionDir;
        r["pid_with_namespace"] = "0";
        r["uid"] = BIGINT(user_id);
        results.push_back(r);
      }
    }
  }
}

std::vector<std::string> listWinJavaPaths(const std::string& keyGlob) {
#ifdef WIN32
  std::vector<std::string> results;

  std::set<std::string> installPathKeys;
  auto status = expandRegistryGlobs(keyGlob, installPathKeys);
  if (!status.ok()) {
    return {};
  }

  QueryData javaInstallLocation;
  for (const auto& installKey : installPathKeys) {
    queryKey(installKey, javaInstallLocation);
    for (const auto& p : javaInstallLocation) {
      if (p.at("name") != "(Default)") {
        continue;
      }
      results.push_back(p.at("data"));
    }
    javaInstallLocation.clear();
  }
  return results;
#else
  return {};
#endif
}

std::vector<std::map<std::string, UserPath>> getJavaUserPathList(
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
        auto dir = path + "/" + path_postfix;

        // Check if directory exists
        if (isDirectory(dir).ok()) {
          std::map<std::string, UserPath> user_path;
          user_path = {
              {"user_id", uid_as_big_int.get()},
              {"path", dir},
              {"type", std::string(path_postfix)},
          };
          paths_list.push_back(user_path);
        }
      }
    }

    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      const auto& uuid_as_string = user.at("uuid");
      auto installPathKey =
          "HKEY_USERS\\" + uuid_as_string + "\\" + kWinJavaInstallKey;
      auto win_paths = listWinJavaPaths(installPathKey);

      for (const auto& win_path : win_paths) {
        std::map<std::string, UserPath> user_path;
        user_path = {
            {"user_id", uid_as_big_int.get()},
            {"path", win_path},
            {"type", std::string("windows")},
        };
        paths_list.push_back(user_path);
      }
    }
  }

  return paths_list;
}

QueryData genJavaPackagesImpl(QueryContext& context, Logger& logger) {
  QueryData results;
  std::set<std::string> paths;
  bool directory_filter = context.constraints.count("directory") > 0 &&
                          context.constraints.at("directory").exists(EQUALS);

  if (directory_filter) {
    paths = context.constraints["directory"].getAll(EQUALS);
  } else {
    for (const auto& path : kJavaPath) {
      std::vector<std::string> sites;
      resolveFilePattern(path, sites);
      for (const auto& site : sites) {
        paths.insert(site);
      }
    }
  }

  // If user has specified `where directory = "path"` then return results early.
  if (directory_filter) {
    return results;
  }

  // Enumerate user installed java packages from Maven and Gradle caches
  auto user_paths = getJavaUserPathList(context);
  for (const auto& user_path : user_paths) {
    const auto& path = user_path.at("path").stringValue;
    const auto& type = user_path.at("type").stringValue;

    if (type.find(".m2/repository") != std::string::npos or type.find(".m2\\repository") != std::string::npos) {
      // Maven repository
      genMavenArtifacts(
          path, results, logger, user_path.at("user_id").intValue);
    } else if (type.find(".gradle/caches") != std::string::npos or type.find(".gradle\\caches") != std::string::npos) {
      // Gradle cache
      genGradleArtifacts(
          path, results, logger, user_path.at("user_id").intValue);
    }
  }
  return results;
}

QueryData genJavaPackages(QueryContext& context) {
  GLOGLogger logger;
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "java_packages", genJavaPackagesImpl);
  } else {
    return genJavaPackagesImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
