/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/info/platform_type.h>
#include <algorithm>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <sys/stat.h>

namespace osquery {
namespace tables {

// Helper function to get the uid of the owner of a file
std::int64_t getFileOwnerUid(const std::string& file_path) {
  struct stat file_stat;
  if (stat(file_path.c_str(), &file_stat) == 0) {
    return static_cast<std::int64_t>(file_stat.st_uid);
  }
  return 0; // Default to root if stat fails
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
    LOG(WARNING) << "Failed to resolve canonical path for " << path << ": " << e.what();
  }
  return path;
}

struct JDKInfo {
  std::string name;
  std::string version;
  std::string vendor;
  std::string path;
  std::string architecture;
};

// Parse a JDK release file to extract metadata
// The release file uses Java properties format: KEY="VALUE" or KEY=VALUE
std::map<std::string, std::string> parseReleaseFile(const std::string& file_path) {
  std::map<std::string, std::string> properties;
  
  std::ifstream file(file_path);
  if (!file.is_open()) {
    return properties;
  }

  std::string line;
  std::regex property_regex(R"(^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\"?([^\"]*)\"?\s*$)");
  
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

// Extract JDK name from path and properties
std::string extractJDKName(const std::string& jdk_path, 
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
  boost::filesystem::path path(jdk_path);
  
  // For macOS: /Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
  // Extract "temurin-17.jdk"
  if (path.filename().string() == "Home" && path.parent_path().filename().string() == "Contents") {
    return path.parent_path().parent_path().filename().string();
  }
  
  // For Linux/Windows or SDKMAN/Jabba style paths
  // Extract the directory name
  return path.filename().string();
}

// Check if a directory is a valid JDK installation
// by looking for the release file and/or bin/java executable
bool isValidJDKInstallation(const std::string& path) {
  boost::filesystem::path jdk_path(path);
  
  // Check for release file (modern JDKs)
  boost::filesystem::path release_file = jdk_path / "release";
  if (pathExists(release_file.string()).ok()) {
    return true;
  }
  
  // Check for bin/java executable (fallback for older JDKs)
  boost::filesystem::path java_bin = jdk_path / "bin" / "java";
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    java_bin = jdk_path / "bin" / "java.exe";
  }
  
  return pathExists(java_bin.string()).ok();
}

// Process a single JDK installation directory
void processJDKInstallation(QueryData& results,
                           const std::string& jdk_path,
                           const std::int64_t& uid) {
  if (!isValidJDKInstallation(jdk_path)) {
    return;
  }
  
  boost::filesystem::path release_file_path = 
      boost::filesystem::path(jdk_path) / "release";
  
  std::map<std::string, std::string> properties;
  if (pathExists(release_file_path.string()).ok()) {
    properties = parseReleaseFile(release_file_path.string());
  }
  
  Row row;
  row["uid"] = BIGINT(uid);
  row["path"] = SQL_TEXT(jdk_path);
  
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
  row["name"] = SQL_TEXT(extractJDKName(jdk_path, properties));
  
  // If vendor is Homebrew, use OpenJDK naming
  std::string vendor_lower = row["vendor"];
  std::transform(vendor_lower.begin(), vendor_lower.end(), vendor_lower.begin(), ::tolower);
  if (vendor_lower == "homebrew" && !row["version"].empty()) {
    row["name"] = SQL_TEXT("OpenJDK " + row["version"]);
  }
  
  results.push_back(row);
}

// Scan system-wide JDK installations (macOS)
void scanSystemJDKs(QueryData& results, std::set<std::string>& seen_paths) {
  if (!isPlatform(PlatformType::TYPE_OSX)) {
    return;
  }
  
  std::string system_jvm_path = "/Library/Java/JavaVirtualMachines";
  if (!pathExists(system_jvm_path).ok()) {
    return;
  }
  
  std::vector<std::string> jdk_dirs;
  listDirectoriesInDirectory(system_jvm_path, jdk_dirs, false);
  
  for (const auto& jdk_dir : jdk_dirs) {
    // macOS JDKs have Contents/Home structure
    std::string home_path = jdk_dir + "/Contents/Home";
    std::string path_to_check = pathExists(home_path).ok() ? home_path : jdk_dir;
    
    // Resolve to canonical path and skip if already seen
    std::string canonical_path = resolveCanonicalPath(path_to_check);
    if (seen_paths.find(canonical_path) != seen_paths.end()) {
      continue; // Skip duplicate/symlink
    }
    seen_paths.insert(canonical_path);
    
    std::int64_t uid = 0;
    
    if (pathExists(home_path).ok()) {
      // Get uid from the release file owner
      std::string release_path = home_path + "/release";
      if (pathExists(release_path).ok()) {
        uid = getFileOwnerUid(release_path);
      } else {
        // Fallback to java executable
        std::string java_path = home_path + "/bin/java";
        if (pathExists(java_path).ok()) {
          uid = getFileOwnerUid(java_path);
        }
      }
      processJDKInstallation(results, home_path, uid);
    } else {
      // Try the directory itself as a fallback
      std::string release_path = jdk_dir + "/release";
      if (pathExists(release_path).ok()) {
        uid = getFileOwnerUid(release_path);
      } else {
        std::string java_path = jdk_dir + "/bin/java";
        if (pathExists(java_path).ok()) {
          uid = getFileOwnerUid(java_path);
        }
      }
      processJDKInstallation(results, jdk_dir, uid);
    }
  }
}

// Scan Homebrew JDK installations (macOS and Linux)
void scanHomebrewJDKs(QueryData& results, std::set<std::string>& seen_paths) {
  // Homebrew installation paths
  // /opt/homebrew for Apple Silicon, /usr/local for Intel
  std::vector<std::string> homebrew_prefixes = {
    "/opt/homebrew/opt",
    "/usr/local/opt"
  };
  
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
      
      if (dir_name != "openjdk" && !boost::algorithm::starts_with(dir_name, "openjdk@")) {
        continue;
      }
      
      // Homebrew OpenJDK structure: 
      // /opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home
      std::string jdk_home = opt_dir + "/libexec/openjdk.jdk/Contents/Home";
      if (pathExists(jdk_home).ok()) {
        // Resolve to canonical path and skip if already seen
        std::string canonical_path = resolveCanonicalPath(jdk_home);
        if (seen_paths.find(canonical_path) != seen_paths.end()) {
          continue; // Skip duplicate/symlink
        }
        seen_paths.insert(canonical_path);
        
        // Get uid from the release file owner
        std::int64_t uid = 0;
        std::string release_path = jdk_home + "/release";
        if (pathExists(release_path).ok()) {
          uid = getFileOwnerUid(release_path);
        } else {
          // Fallback to java executable
          std::string java_path = jdk_home + "/bin/java";
          if (pathExists(java_path).ok()) {
            uid = getFileOwnerUid(java_path);
          }
        }
        processJDKInstallation(results, jdk_home, uid);
      }
    }
  }
}

// Scan user-specific JDK installations
void scanUserJDKs(QueryData& results,
                 const std::string& user_home,
                 const std::int64_t& uid,
                 std::set<std::string>& seen_paths) {
  std::vector<std::string> search_paths;
  
  if (isPlatform(PlatformType::TYPE_OSX)) {
    // macOS user-specific installations
    search_paths.push_back(user_home + "/Library/Java/JavaVirtualMachines");
  }
  
  // SDKMAN installations (all platforms)
  search_paths.push_back(user_home + "/.sdkman/candidates/java");
  
  // Jabba installations (all platforms)
  search_paths.push_back(user_home + "/.jabba/jdk");
  
  for (const auto& search_path : search_paths) {
    if (!pathExists(search_path).ok()) {
      continue;
    }
    
    std::vector<std::string> jdk_dirs;
    listDirectoriesInDirectory(search_path, jdk_dirs, false);
    
    for (const auto& jdk_dir : jdk_dirs) {
      std::string path_to_process;
      
      // For macOS Library/Java paths and Jabba, check for Contents/Home structure
      // SDKMAN uses flat directory structure
      if ((isPlatform(PlatformType::TYPE_OSX) && 
           search_path.find("Library/Java/JavaVirtualMachines") != std::string::npos) ||
          search_path.find(".jabba/jdk") != std::string::npos) {
        std::string home_path = jdk_dir + "/Contents/Home";
        if (pathExists(home_path).ok()) {
          path_to_process = home_path;
        } else {
          path_to_process = jdk_dir;
        }
      } else {
        // For SDKMAN, the directory itself is the JDK home
        path_to_process = jdk_dir;
      }
      
      // Resolve to canonical path and skip if already seen
      std::string canonical_path = resolveCanonicalPath(path_to_process);
      if (seen_paths.find(canonical_path) != seen_paths.end()) {
        continue; // Skip duplicate/symlink
      }
      seen_paths.insert(canonical_path);
      
      processJDKInstallation(results, path_to_process, uid);
    }
  }
}

QueryData genJDK(QueryContext& context) {
  QueryData results;
  std::set<std::string> seen_paths; // Track canonical paths to avoid duplicates

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
    scanUserJDKs(results, user_home, uid_as_big_int.get(), seen_paths);
  }

  // Scan system-wide installations (macOS only)
  if (isPlatform(PlatformType::TYPE_OSX)) {
    scanSystemJDKs(results, seen_paths);
  }
  
  // Scan Homebrew installations (macOS and Linux)
  if (isPlatform(PlatformType::TYPE_OSX) || isPlatform(PlatformType::TYPE_LINUX)) {
    scanHomebrewJDKs(results, seen_paths);
  }

  return results;
}
} // namespace tables
} // namespace osquery
