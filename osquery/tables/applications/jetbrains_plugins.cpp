/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/predicate.hpp>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/applications/jetbrains_plugins.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/scope_guard.h>
#include <regex>

#define LIBARCHIVE_STATIC
#include <archive.h>
#include <archive_entry.h>

namespace osquery {
namespace tables {
// Function to convert JetBrainsProductType enum to string
const std::string getProductName(const JetBrainsProductType type) {
  auto product = kProductTypeToString.find(type);
  return product->second;
}

struct FileData {
  std::string path;
  std::vector<char> content;
};

FileData extractSpecificFileFromArchive(const std::string& archive_file_path,
                                        const std::string& target_file_path) {
  struct archive* archive;
  struct archive_entry* entry;
  int result;
  FileData file_data;

  archive = archive_read_new();
  archive_read_support_format_all(archive);
  archive_read_support_filter_all(archive);

  auto archive_guard = osquery::scope_guard::create([&archive]() {
    if (archive != nullptr) {
      int free_result = archive_read_free(archive);
      if (free_result != ARCHIVE_OK) {
        VLOG(1) << "Failed to close zip file: " << archive_error_string(archive)
                << std::endl;
      }
    }
  });

  result = archive_read_open_filename(
      archive, archive_file_path.c_str(), 10240); // 10KB buffer
  if (result != ARCHIVE_OK) {
    VLOG(1) << "Failed to open zip file: " << archive_error_string(archive)
            << std::endl;

    return file_data;
  }

  while (archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
    // Get the current file from the archive entry
    const char* currentFile = archive_entry_pathname(entry);
    boost::filesystem::path currentPath(currentFile);
    boost::filesystem::path targetPath(target_file_path);

    if (currentPath == targetPath) {
      // Found the target file in the archive
      file_data.path = currentFile;

      const void* buffer;
      size_t size;
      int64_t offset;

      while (archive_read_data_block(archive, &buffer, &size, &offset) ==
             ARCHIVE_OK) {
        file_data.content.insert(file_data.content.end(),
                                 (const char*)buffer,
                                 (const char*)buffer + size);
      }

      if (archive_errno(archive) != 0) {
        VLOG(1) << "Error reading data block: " << archive_error_string(archive)
                << std::endl;
      }

      break;
    }
    // Move to the next entry
    archive_read_data_skip(archive);
  }

  return file_data;
}

struct PluginAttributes {
  std::string name;
  std::string vendor;
  std::string version;
};

// Function to extract the contents of a specific tag
std::string getContentFromTag(const std::string& xml,
                              const std::string& tag_name) {
  std::regex tagRegex("<" + tag_name + "[\\s\\S]*?>([\\s\\S]*?)<\\/" +
                      tag_name + ">");
  std::smatch match;

  if (std::regex_search(xml, match, tagRegex)) {
    // match[0] is the entire tag with contents <TagName>contents</TagName>
    // match[1] is the contents of the tag
    return match[1];
  }
  return "";
}

// Function to parse the plugin.xml file
// and extract the attributes we are interested in
PluginAttributes parsePluginXml(const std::string& xml_content) {
  PluginAttributes attributes;

  // Example
  // <name>Osquery Plugin</name>
  // Uses Title Case
  auto name_pos = xml_content.find("<name>");
  if (name_pos != std::string::npos) {
    attributes.name = getContentFromTag(xml_content, "name");
  }

  // Example
  // <vendor>Osquery</vendor>
  // <vendor
  //     url="https://www.osquery.io"
  //     email="help@osquery.io">
  //   Osquery
  // </vendor>
  // url (optional)
  // email (optional)
  auto vendor_pos = xml_content.find("<vendor");
  if (vendor_pos != std::string::npos) {
    attributes.vendor = getContentFromTag(xml_content, "vendor");
  }

  // Example
  // <version>1.3.18</version>
  // Uses JetBrains Marketplace Semantic Versioning
  // https://plugins.jetbrains.com/docs/marketplace/semver.html
  auto version_pos = xml_content.find("<version>");
  if (version_pos != std::string::npos) {
    attributes.version = getContentFromTag(xml_content, "version");
  }

  return attributes;
}

// Extract the plugin.xml file from the plugin archive
FileData getPluginXMLFile(const std::string& jar_file_path) {
  // The plugin.xml configuration file contains all the information about the
  // plugin, which is displayed in the plugins' settings dialog
  // https://plugins.jetbrains.com/docs/intellij/plugin-configuration-file.html
  std::string target_file_path;
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    target_file_path = "META-INF\\plugin.xml";
  } else {
    target_file_path = "META-INF/plugin.xml";
  }
  FileData file_data =
      extractSpecificFileFromArchive(jar_file_path, target_file_path);

  return file_data;
}

// Given a jar file path, attempts to extract the plugin.xml file
// If plugin.xml is not found, returns nullptr
// If plugin.xml is found, returns the PluginAttributes
std::unique_ptr<PluginAttributes> attributesFromJar(
    const std::string& jar_file_path) {
  auto file_data = getPluginXMLFile(jar_file_path);

  if (file_data.content.empty()) {
    return nullptr;
  }
  std::string xml_content(file_data.content.begin(), file_data.content.end());

  return std::make_unique<PluginAttributes>(parsePluginXml(xml_content));
}

/*
 * The folllowing two methods fileNameIsLikeVersionedLibraryName &
 * putMoreLikelyPluginJarsFirst have been extracted from the community edition
 * of intellij: https://github.com/JetBrains/intellij-community The original
 * code was written in kotlin and this is the translated c++ code Their names
 * are identical to the original source code so they are easy to find Copyright
 * 2000-2024 JetBrains s.r.o. and contributors. Use of this source code is
 * governed by the Apache 2.0 license.
 */

bool fileNameIsLikeVersionedLibraryName(const std::string& name) {
  size_t i = name.rfind('-');
  if (i == std::string::npos) {
    return false;
  }
  if (i + 1 < name.length()) {
    char c = name[i + 1];
    if (std::isdigit(c))
      return true;
    if ((c == 'm' || c == 'M') && i + 2 < name.length() &&
        std::isdigit(name[i + 2]))
      return true;
  }
  return false;
}

// Sorts the files heuristically to load the plugin jar containing plugin.xml
// * File name preference:
// * a) last order for files with resources in name, like resources_en.jar
// * b) last order for files that have `-digit` suffix is the name e.g.,
// completion-ranking.jar is before `gson-2.8.0.jar` or `junit-m5.jar`
// * c) JAR with name close to plugin's directory name, e.g., kotlin-XXX.jar is
// before all-open-XXX.jar
// * d) Shorter name, e.g., android.jar is before android-base-common.jar
// Parameters:
// plugin_dir_name: the name of the plugin directory under lib
// Example:
//   "github-copilot-intellij"
// files_in_lib_under_plugin_dir: a list of files under lib
// Example:
//   "/<absolute
//   path>/JetBrains/IntelliJIdea2024.3/plugins/aws-toolkit-jetbrains-standalone/lib/jetbrains-ultimate.jar"
void putMoreLikelyPluginJarsFirst(
    const std::string& plugin_dir_name,
    std::vector<std::string>& files_in_lib_under_plugin_dir) {
  std::sort(
      files_in_lib_under_plugin_dir.begin(),
      files_in_lib_under_plugin_dir.end(),
      [&plugin_dir_name](const std::string& o1, const std::string& o2) {
        std::string o1_name = boost::filesystem::path(o1).filename().string();
        std::string o2_name = boost::filesystem::path(o2).filename().string();
        bool o1_starts_with_resources = o1_name.rfind("resources", 0) == 0;
        bool o2_starts_with_resources = o2_name.rfind("resources", 0) == 0;
        if (o2_starts_with_resources != o1_starts_with_resources) {
          // Files with "resources" in name go last
          return !o1_starts_with_resources && o2_starts_with_resources;
        }

        bool o1_is_versioned = fileNameIsLikeVersionedLibraryName(o1_name);
        bool o2_is_versioned = fileNameIsLikeVersionedLibraryName(o2_name);
        if (o2_is_versioned != o1_is_versioned) {
          // Files with digits in suffix go last
          return !o1_is_versioned && o2_is_versioned;
        }

        bool o1_starts_with_needed_name =
            boost::algorithm::istarts_with(o1_name, plugin_dir_name);
        bool o2_starts_with_needed_name =
            boost::algorithm::istarts_with(o2_name, plugin_dir_name);
        if (o2_starts_with_needed_name != o1_starts_with_needed_name) {
          // Files starting with plugin_dir_name go first
          return o1_starts_with_needed_name && !o2_starts_with_needed_name;
        }

        bool o2_ends_with_idea =
            boost::algorithm::iends_with(o2_name, "-idea.jar");
        bool o1_ends_with_idea =
            boost::algorithm::iends_with(o1_name, "-idea.jar");
        if (o2_ends_with_idea != o1_ends_with_idea) {
          // Files ending with -idea.jar go last
          return !o1_ends_with_idea && o2_ends_with_idea;
        }

        bool o1_is_db_plugin = o1_name == "database-plugin.jar";
        bool o2_is_db_plugin = o2_name == "database-plugin.jar";
        if (o2_is_db_plugin != o1_is_db_plugin) {
          // Files named database-plugin.jar come last
          return !o1_is_db_plugin && o2_is_db_plugin;
        }

        return static_cast<int>(o1_name.length()) <
               static_cast<int>(o2_name.length());
      });
}
/*
 * End Intellij Community Edition code
 */

void genPlugins(QueryData& results,
                const ProductPathMap paths_to_traverse,
                const std::string& user_path_prefix,
                const std::int64_t& uid) {
  for (const auto& [product_type, path] : paths_to_traverse) {
    std::string full_path;
    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      full_path = user_path_prefix + "\\" + path;
    } else {
      full_path = user_path_prefix + "/" + path;
    }

    std::vector<std::string> plugin_paths;
    resolveFilePattern(full_path, plugin_paths);
    for (const auto& plugin_path : plugin_paths) {
      // "Plugin Without Dependencies"
      // The plugin is a .jar file
      std::vector<std::string> plugin_files;
      listFilesInDirectory(plugin_path, plugin_files, false);
      for (const auto& plugin_jar_file : plugin_files) {
        std::unique_ptr<PluginAttributes> attributes =
            attributesFromJar(plugin_jar_file);
        if (!attributes) {
          // Skip this plugin, as we cannot find the plugin.xml file.
          // This should not happen. Even in the case of Kotlin-based plugins
          // that use build.gradle.kts, they will still contain a plugin.xml
          // file.
          VLOG(1) << "Failed to find plugin.xml from: " << plugin_jar_file;
          continue;
        }

        Row row;
        row["product_type"] = SQL_TEXT(getProductName(product_type));
        row["uid"] = BIGINT(uid);
        row["path"] = SQL_TEXT(plugin_jar_file);
        row["name"] = SQL_TEXT(attributes->name);
        row["vendor"] = SQL_TEXT(attributes->vendor);
        row["version"] = SQL_TEXT(attributes->version);
        results.push_back(row);
      }

      // "Plugin With Dependencies"
      // The plugin is a folder
      // The plugin .jar file is placed in the /lib within this folder, together
      // with all required bundled libraries.
      std::vector<std::string> plugins_directories;
      listDirectoriesInDirectory(plugin_path, plugins_directories, false);
      for (const auto& plugin_directory : plugins_directories) {
        // plugin_directory Example:
        // /<absolute
        // path>/JetBrains/IntelliJIdea2024.3/plugins/aws-toolkit-jetbrains-standalone

        std::string plugin_lib_directory;
        if (isPlatform(PlatformType::TYPE_WINDOWS)) {
          plugin_lib_directory = plugin_directory + "\\lib";
        } else {
          plugin_lib_directory = plugin_directory + "/lib";
        }
        std::vector<std::string> plugin_lib_files;
        listFilesInDirectory(plugin_lib_directory, plugin_lib_files, false);
        // plugin_lib_files
        // An array of full string paths to files
        // Example:
        // [
        //    /<absolute
        //    path>/JetBrains/IntelliJIdea2024.3/plugins/aws-toolkit-jetbrains-standalone/lib/jetbrains-ultimate.jar
        //    ...
        // ]
        std::string plugin_dir_name;
        if (isPlatform(PlatformType::TYPE_WINDOWS)) {
          plugin_dir_name =
              plugin_directory.substr(plugin_directory.find_last_of("\\") + 1);
        } else {
          plugin_dir_name =
              plugin_directory.substr(plugin_directory.find_last_of("/\\") + 1);
        }
        // plugin_dir_name
        // The name of the plugin directory under lib
        // Example:
        // aws-toolkit-jetbrains-standalone
        putMoreLikelyPluginJarsFirst(plugin_dir_name, plugin_lib_files);

        std::unique_ptr<PluginAttributes> attributes;
        for (const auto& jar_file : plugin_lib_files) {
          // Iterate through the jar files in the plugin lib directory
          // and try to find the plugin.xml file
          attributes = attributesFromJar(jar_file);
          if (attributes) {
            break;
          }
        }
        if (!attributes) {
          // Skip this plugin, as we cannot find the plugin.xml file in any of
          // the jar files. This should not happen. Even in the case of
          // Kotlin-based plugins that use build.gradle.kts, they will still
          // contain a plugin.xml file.
          VLOG(1) << "Failed to find plugin.xml from: " << plugin_directory;
          continue;
        }

        Row row;
        row["product_type"] = SQL_TEXT(getProductName(product_type));
        row["uid"] = BIGINT(uid);
        row["path"] = SQL_TEXT(plugin_directory);
        row["name"] = SQL_TEXT(attributes->name);
        row["vendor"] = SQL_TEXT(attributes->vendor);
        row["version"] = SQL_TEXT(attributes->version);
        results.push_back(row);
      }
    }
  }
}

QueryData genJetBrainsPlugins(QueryContext& context) {
  QueryData results;

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
    const auto& user_path_prefix = user.at("directory");

    ProductPathMap paths_to_traverse;
    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      paths_to_traverse = kWindowsPathList;
    } else if (isPlatform(PlatformType::TYPE_OSX)) {
      paths_to_traverse = kMacOsPathList;
    } else {
      paths_to_traverse = kLinuxPathList;
    }

    genPlugins(
        results, paths_to_traverse, user_path_prefix, uid_as_big_int.get());
  }

  return results;
}
} // namespace tables
} // namespace osquery
