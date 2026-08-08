/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <map>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/info/platform_type.h>
#include <regex>
#include <set>
#include <sys/stat.h>

namespace osquery {
namespace tables {

// Helper function to get the uid of the owner of a file
std::int64_t getFileOwnerUid(const std::string& file_path) {
#ifndef WIN32
  struct stat file_stat;
  if (stat(file_path.c_str(), &file_stat) == 0) {
    return static_cast<std::int64_t>(file_stat.st_uid);
  }
#endif
  return 0; // Default to root if stat fails or is unsupported
}

// Helper function to resolve a path to its canonical form
// This handles symlinks by resolving them to their targets
std::string resolveCanonicalPath(const std::string& path) {
  try {
    boost::filesystem::path p(path);
    if (boost::filesystem::exists(p)) {
      return boost::filesystem::canonical(p).string();
    }
  } catch (const boost::filesystem::filesystem_error& e) {
    // If we can't resolve, return the original path
    VLOG(1) << "Failed to resolve canonical path for " << path << ": "
            << e.what();
  }
  return path;
}

// Parse a JVM release file to extract metadata
// The release file uses Java properties format: KEY="VALUE" or KEY=VALUE
std::map<std::string, std::string> parseReleaseFile(
    const std::string& file_path) {
  std::map<std::string, std::string> properties;

  std::ifstream file(file_path);
  if (!file.is_open()) {
    return properties;
  }

  std::string line;
  std::regex property_regex(
      R"(^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\"?([^\"]*)\"?\s*$)");

  while (std::getline(file, line)) {
    // Skip empty lines and comments
    boost::algorithm::trim(line);
    if (line.empty() || line[0] == '#') {
      continue;
    }

    std::smatch match;
    if (std::regex_search(line, match, property_regex)) {
      std::string key = match[1].str();
      std::string value = match[2].str();

      // Remove surrounding quotes if present
      if (!value.empty() && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.length() - 2);
      }

      properties[key] = value;
    }
  }

  return properties;
}

// Extract JVM name from path and properties
std::string extractJVMName(
    const std::string& jvm_path,
    const std::map<std::string, std::string>& properties) {
  // Try to get a meaningful name from properties first
  if (properties.count("IMPLEMENTOR")) {
    auto implementor = properties.at("IMPLEMENTOR");
    if (properties.count("JAVA_VERSION")) {
      return implementor + " JDK " + properties.at("JAVA_VERSION");
    }
    return implementor + " JDK";
  }

  // Fall back to extracting from path
  boost::filesystem::path path(jvm_path);

  // For macOS: /Library/Java/JavaVirtualMachines/temurin-17.jvm/Contents/Home
  // Extract "temurin-17.jvm"
  if (path.filename().string() == "Home" &&
      path.parent_path().filename().string() == "Contents") {
    return path.parent_path().parent_path().filename().string();
  }

  // For Linux/Windows or SDKMAN/Jabba style paths
  // Extract the directory name
  return path.filename().string();
}

// Check if a directory is a valid JVM installation
// by looking for the release file and/or bin/java executable
bool isValidJVMInstallation(const std::string& path) {
  boost::filesystem::path jvm_path(path);

  // Check for release file (modern JVMs)
  boost::filesystem::path release_file = jvm_path / "release";
  if (pathExists(release_file.string()).ok()) {
    return true;
  }

  // Check for bin/java executable (fallback for older JVMs)
  boost::filesystem::path java_bin = jvm_path / "bin" / "java";
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    java_bin = jvm_path / "bin" / "java.exe";
  }

  return pathExists(java_bin.string()).ok();
}

// Process a single JVM installation directory
void processJVMInstallation(QueryData& results,
                            const std::string& jvm_path,
                            const std::int64_t& uid) {
  if (!isValidJVMInstallation(jvm_path)) {
    return;
  }

  boost::filesystem::path release_file_path =
      boost::filesystem::path(jvm_path) / "release";

  std::map<std::string, std::string> properties;
  if (pathExists(release_file_path.string()).ok()) {
    properties = parseReleaseFile(release_file_path.string());
  }

  Row row;
  row["uid"] = BIGINT(uid);
  row["path"] = SQL_TEXT(jvm_path);

  // Extract vendor (IMPLEMENTOR is the standard field for vendor)
  if (properties.count("IMPLEMENTOR")) {
    row["vendor"] = SQL_TEXT(properties["IMPLEMENTOR"]);
  } else if (properties.count("JAVA_VENDOR")) {
    row["vendor"] = SQL_TEXT(properties["JAVA_VENDOR"]);
  } else {
    row["vendor"] = SQL_TEXT("");
  }

  // If vendor is empty and BUILD_TYPE is "commercial", set vendor to Oracle
  if (row["vendor"].empty() && properties.count("BUILD_TYPE")) {
    if (properties.at("BUILD_TYPE") == "commercial") {
      row["vendor"] = SQL_TEXT("Oracle");
    }
  }

  // Extract version
  if (properties.count("JAVA_VERSION")) {
    row["version"] = SQL_TEXT(properties["JAVA_VERSION"]);
  } else if (properties.count("JAVA_RUNTIME_VERSION")) {
    row["version"] = SQL_TEXT(properties["JAVA_RUNTIME_VERSION"]);
  } else {
    row["version"] = SQL_TEXT("");
  }

  if (properties.count("OS_ARCH")) {
    row["architecture"] = SQL_TEXT(properties["OS_ARCH"]);
  } else {
    row["architecture"] = SQL_TEXT("");
  }

  // Extract or generate name
  row["name"] = SQL_TEXT(extractJVMName(jvm_path, properties));

  // If vendor is Homebrew, use OpenJDK naming
  std::string vendor_lower = row["vendor"];
  boost::algorithm::to_lower(vendor_lower);
  if (vendor_lower == "homebrew" && !row["version"].empty()) {
    row["name"] = SQL_TEXT("OpenJDK " + row["version"]);
  }

  results.push_back(row);
}

// Scan system-wide JVM installations (macOS)
void scanSystemJVMs(
    QueryData& results,
    std::set<std::pair<std::int64_t, std::string>>& seen_paths) {
  if (!isPlatform(PlatformType::TYPE_OSX)) {
    return;
  }

  std::string system_jvm_path = "/Library/Java/JavaVirtualMachines";
  if (!pathExists(system_jvm_path).ok()) {
    return;
  }

  std::vector<std::string> jvm_dirs;
  listDirectoriesInDirectory(system_jvm_path, jvm_dirs, false);

  for (const auto& jvm_dir : jvm_dirs) {
    // macOS JVMs have Contents/Home structure
    std::string home_path =
        (boost::filesystem::path(jvm_dir) / "Contents" / "Home").string();
    std::string path_to_check =
        pathExists(home_path).ok() ? home_path : jvm_dir;

    // Resolve to canonical path
    std::string canonical_path = resolveCanonicalPath(path_to_check);

    std::int64_t uid = 0;

    if (pathExists(home_path).ok()) {
      // Get uid from the release file owner
      std::string release_path =
          (boost::filesystem::path(home_path) / "release").string();
      if (pathExists(release_path).ok()) {
        uid = getFileOwnerUid(release_path);
      } else {
        // Fallback to java executable
        std::string java_path =
            (boost::filesystem::path(home_path) / "bin" / "java").string();
        if (pathExists(java_path).ok()) {
          uid = getFileOwnerUid(java_path);
        }
      }

      // Skip if already seen for this uid
      if (seen_paths.find(std::make_pair(uid, canonical_path)) !=
          seen_paths.end()) {
        continue; // Skip duplicate/symlink
      }
      seen_paths.insert(std::make_pair(uid, canonical_path));

      processJVMInstallation(results, home_path, uid);
    } else {
      // Try the directory itself as a fallback
      std::string release_path =
          (boost::filesystem::path(jvm_dir) / "release").string();
      if (pathExists(release_path).ok()) {
        uid = getFileOwnerUid(release_path);
      } else {
        std::string java_path =
            (boost::filesystem::path(jvm_dir) / "bin" / "java").string();
        if (pathExists(java_path).ok()) {
          uid = getFileOwnerUid(java_path);
        }
      }

      // Skip if already seen for this uid
      if (seen_paths.find(std::make_pair(uid, canonical_path)) !=
          seen_paths.end()) {
        continue; // Skip duplicate/symlink
      }
      seen_paths.insert(std::make_pair(uid, canonical_path));

      processJVMInstallation(results, jvm_dir, uid);
    }
  }
}

// Scan system-wide JVM installations (Windows)
void scanWindowsSystemJVMs(
    QueryData& results,
    std::set<std::pair<std::int64_t, std::string>>& seen_paths) {
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    return;
  }

  std::vector<std::string> system_jvm_paths = {
      "C:/Program Files/Java",
      "C:/Program Files/Eclipse Adoptium",
      "C:/Program Files/Eclipse Foundation",
      "C:/Program Files/Amazon Corretto",
      "C:/Program Files/Microsoft",
      "C:/Program Files/Zulu",
      "C:/Program Files (x86)/Java",
      "C:/Program Files (x86)/Eclipse Adoptium",
      "C:/Program Files (x86)/Amazon Corretto",
      "C:/Program Files (x86)/Microsoft",
      "C:/Program Files (x86)/Zulu"};

  for (const auto& system_path : system_jvm_paths) {
    if (!pathExists(system_path).ok()) {
      continue;
    }

    std::vector<std::string> jvm_dirs;
    listDirectoriesInDirectory(system_path, jvm_dirs, false);

    for (const auto& jvm_dir : jvm_dirs) {
      // Resolve to canonical path
      std::string canonical_path = resolveCanonicalPath(jvm_dir);

      std::int64_t uid = 0;

      // Get uid from the release file owner
      std::string release_path =
          (boost::filesystem::path(jvm_dir) / "release").string();
      if (pathExists(release_path).ok()) {
        uid = getFileOwnerUid(release_path);
      } else {
        // Fallback to java executable
        std::string java_path =
            (boost::filesystem::path(jvm_dir) / "bin" / "java.exe").string();
        if (pathExists(java_path).ok()) {
          uid = getFileOwnerUid(java_path);
        }
      }

      // Skip if already seen for this uid
      if (seen_paths.find(std::make_pair(uid, canonical_path)) !=
          seen_paths.end()) {
        continue; // Skip duplicate/symlink
      }
      seen_paths.insert(std::make_pair(uid, canonical_path));

      processJVMInstallation(results, jvm_dir, uid);
    }
  }
}

// Scan system-wide JVM installations (Linux)
void scanLinuxSystemJVMs(
    QueryData& results,
    std::set<std::pair<std::int64_t, std::string>>& seen_paths) {
  if (!isPlatform(PlatformType::TYPE_LINUX)) {
    return;
  }

  std::string system_jvm_path = "/usr/lib/jvm";
  if (!pathExists(system_jvm_path).ok()) {
    return;
  }

  std::vector<std::string> jvm_dirs;
  listDirectoriesInDirectory(system_jvm_path, jvm_dirs, false);

  for (const auto& jvm_dir : jvm_dirs) {
    // Resolve to canonical path
    std::string canonical_path = resolveCanonicalPath(jvm_dir);

    std::int64_t uid = 0;

    // Get uid from the release file owner
    std::string release_path =
        (boost::filesystem::path(jvm_dir) / "release").string();
    if (pathExists(release_path).ok()) {
      uid = getFileOwnerUid(release_path);
    } else {
      // Fallback to java executable
      std::string java_path =
          (boost::filesystem::path(jvm_dir) / "bin" / "java").string();
      if (pathExists(java_path).ok()) {
        uid = getFileOwnerUid(java_path);
      }
    }

    // Skip if already seen for this uid
    if (seen_paths.find(std::make_pair(uid, canonical_path)) !=
        seen_paths.end()) {
      continue; // Skip duplicate/symlink
    }
    seen_paths.insert(std::make_pair(uid, canonical_path));

    processJVMInstallation(results, jvm_dir, uid);
  }
}

// Scan Homebrew JVM installations (macOS and Linux)
void scanHomebrewJVMs(
    QueryData& results,
    std::set<std::pair<std::int64_t, std::string>>& seen_paths) {
  // Homebrew installation paths
  // /opt/homebrew for Apple Silicon, /usr/local for Intel
  std::vector<std::string> homebrew_prefixes = {
      "/opt/homebrew/opt", "/usr/local/opt", "/home/linuxbrew/.linuxbrew/opt"};

  for (const auto& homebrew_prefix : homebrew_prefixes) {
    if (!pathExists(homebrew_prefix).ok()) {
      continue;
    }

    // List all directories in the Homebrew opt directory
    std::vector<std::string> opt_dirs;
    listDirectoriesInDirectory(homebrew_prefix, opt_dirs, false);

    for (const auto& opt_dir : opt_dirs) {
      // Check if this is an openjdk installation
      // e.g., openjdk, openjdk@17, openjdk@21, openjdk@25
      boost::filesystem::path opt_path(opt_dir);
      std::string dir_name = opt_path.filename().string();

      if (dir_name != "openjdk" &&
          !boost::algorithm::starts_with(dir_name, "openjdk@")) {
        continue;
      }

      // Homebrew OpenJDK structure:
      // /opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home
      std::string jvm_home = (boost::filesystem::path(opt_dir) / "libexec" /
                              "openjdk.jdk" / "Contents" / "Home")
                                 .string();
      if (pathExists(jvm_home).ok()) {
        // Resolve to canonical path
        std::string canonical_path = resolveCanonicalPath(jvm_home);

        // Get uid from the release file owner
        std::int64_t uid = 0;
        std::string release_path =
            (boost::filesystem::path(jvm_home) / "release").string();
        if (pathExists(release_path).ok()) {
          uid = getFileOwnerUid(release_path);
        } else {
          // Fallback to java executable
          std::string java_path =
              (boost::filesystem::path(jvm_home) / "bin" / "java").string();
          if (pathExists(java_path).ok()) {
            uid = getFileOwnerUid(java_path);
          }
        }

        // Skip if already seen for this uid
        if (seen_paths.find(std::make_pair(uid, canonical_path)) !=
            seen_paths.end()) {
          continue; // Skip duplicate/symlink
        }
        seen_paths.insert(std::make_pair(uid, canonical_path));

        processJVMInstallation(results, jvm_home, uid);
      }
    }
  }
}

// Scan user-specific JVM installations
void scanUserJVMs(QueryData& results,
                  const std::string& user_home,
                  const std::int64_t& uid,
                  std::set<std::pair<std::int64_t, std::string>>& seen_paths) {
  boost::filesystem::path user_home_path(user_home);
  std::vector<std::string> search_paths;

  if (isPlatform(PlatformType::TYPE_OSX)) {
    // macOS user-specific installations
    search_paths.push_back(
        (user_home_path / "Library" / "Java" / "JavaVirtualMachines").string());
  }

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    // Windows user-specific installations (e.g., Microsoft JVM)
    search_paths.push_back(
        (user_home_path / "AppData" / "Local" / "Programs" / "Microsoft")
            .string());
  }

  // SDKMAN installations (all platforms)
  search_paths.push_back(
      (user_home_path / ".sdkman" / "candidates" / "java").string());

  // Jabba installations (all platforms)
  search_paths.push_back((user_home_path / ".jabba" / "jdk").string());

  for (const auto& search_path : search_paths) {
    if (!pathExists(search_path).ok()) {
      continue;
    }

    std::vector<std::string> jvm_dirs;
    listDirectoriesInDirectory(search_path, jvm_dirs, false);

    for (const auto& jvm_dir : jvm_dirs) {
      std::string path_to_process;

      // Check for Contents/Home structure on macOS (Library/Java and Jabba)
      // On Windows/Linux, Jabba uses flat structure like SDKMAN
      if (isPlatform(PlatformType::TYPE_OSX) &&
          (search_path.find("Library/Java/JavaVirtualMachines") !=
               std::string::npos ||
           search_path.find(".jabba/jdk") != std::string::npos)) {
        std::string home_path =
            (boost::filesystem::path(jvm_dir) / "Contents" / "Home").string();
        if (pathExists(home_path).ok()) {
          path_to_process = home_path;
        } else {
          path_to_process = jvm_dir;
        }
      } else {
        // For SDKMAN and Windows/Linux Jabba, the directory itself is the JVM
        // home
        path_to_process = jvm_dir;
      }

      // Resolve to canonical path and skip if already seen for this uid (avoids
      // symlink duplicates)
      std::string canonical_path = resolveCanonicalPath(path_to_process);
      if (seen_paths.find(std::make_pair(uid, canonical_path)) !=
          seen_paths.end()) {
        continue; // Skip duplicate/symlink
      }
      seen_paths.insert(std::make_pair(uid, canonical_path));

      processJVMInstallation(results, path_to_process, uid);
    }
  }
}

QueryData genJVM(QueryContext& context) {
  QueryData results;
  std::set<std::pair<std::int64_t, std::string>>
      seen_paths; // Track (uid, canonical_path) pairs to avoid duplicates

  auto users = usersFromContext(context);
  for (const auto& user : users) {
    if (user.count("uid") == 0 || user.count("directory") == 0) {
      continue;
    }

    const auto& uid_as_string = user.at("uid");
    auto uid_as_big_int = tryTo<int64_t>(uid_as_string, 10);
    if (uid_as_big_int.isError()) {
      LOG(ERROR) << "Invalid uid field returned: " << uid_as_string;
      continue;
    }
    const auto& user_home = user.at("directory");

    // Scan user-specific installations
    scanUserJVMs(results, user_home, uid_as_big_int.get(), seen_paths);
  }

  // Scan system-wide installations (macOS only)
  if (isPlatform(PlatformType::TYPE_OSX)) {
    scanSystemJVMs(results, seen_paths);
  }

  // Scan system-wide installations (Windows only)
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    scanWindowsSystemJVMs(results, seen_paths);
  }

  // Scan system-wide installations (Linux only)
  if (isPlatform(PlatformType::TYPE_LINUX)) {
    scanLinuxSystemJVMs(results, seen_paths);
  }

  // Scan Homebrew installations (macOS and Linux)
  if (isPlatform(PlatformType::TYPE_OSX) ||
      isPlatform(PlatformType::TYPE_LINUX)) {
    scanHomebrewJVMs(results, seen_paths);
  }

  return results;
}
} // namespace tables
} // namespace osquery
