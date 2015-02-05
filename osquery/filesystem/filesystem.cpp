/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <exception>
#include <sstream>
#include <iostream>

#include <fcntl.h>
#include <sys/stat.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace pt = boost::property_tree;
namespace fs = boost::filesystem;

namespace osquery {

Status writeTextFile(const boost::filesystem::path& path,
                     const std::string& content,
                     int permissions,
                     bool force_permissions) {
  // Open the file with the request permissions.
  int output_fd =
      open(path.c_str(), O_CREAT | O_APPEND | O_WRONLY, permissions);
  if (output_fd <= 0) {
    return Status(1, "Could not create file: " + path.string());
  }

  // If the file existed with different permissions before our open
  // they must be restricted.
  if (chmod(path.c_str(), permissions) != 0) {
    // Could not change the file to the requested permissions.
    return Status(1, "Failed to change permissions for file: " + path.string());
  }

  auto bytes = write(output_fd, content.c_str(), content.size());
  if (bytes != content.size()) {
    close(output_fd);
    return Status(1, "Failed to write contents to file: " + path.string());
  }

  close(output_fd);
  return Status(0, "OK");
}

Status readFile(const boost::filesystem::path& path, std::string& content) {
  auto path_exists = pathExists(path);
  if (!path_exists.ok()) {
    return path_exists;
  }

  std::stringstream buffer;
  fs::ifstream file_h(path);
  if (file_h.is_open()) {
    buffer << file_h.rdbuf();
    if (file_h.bad()) {
      return Status(1, "Error reading file: " + path.string());
    }
    content.assign(std::move(buffer.str()));
  } else {
    return Status(1, "Could not open file: " + path.string());
  }

  return Status(0, "OK");
}

Status isWritable(const boost::filesystem::path& path) {
  auto path_exists = pathExists(path);
  if (!path_exists.ok()) {
    return path_exists;
  }

  if (access(path.c_str(), W_OK) == 0) {
    return Status(0, "OK");
  }
  return Status(1, "Path is not writable: " + path.string());
}

Status isReadable(const boost::filesystem::path& path) {
  auto path_exists = pathExists(path);
  if (!path_exists.ok()) {
    return path_exists;
  }

  if (access(path.c_str(), R_OK) == 0) {
    return Status(0, "OK");
  }
  return Status(1, "Path is not readable: " + path.string());
}

Status pathExists(const boost::filesystem::path& path) {
  if (path.empty()) {
    return Status(1, "-1");
  }

  // A tri-state determination of presence
  try {
    if (!boost::filesystem::exists(path)) {
      return Status(1, "0");
    }
  } catch (boost::filesystem::filesystem_error e) {
    return Status(1, e.what());
  }
  return Status(0, "1");
}

Status listFilesInDirectory(const boost::filesystem::path& path,
                            std::vector<std::string>& results) {
  try {
    if (!boost::filesystem::exists(path)) {
      return Status(1, "Directory not found: " + path.string());
    }

    if (!boost::filesystem::is_directory(path)) {
      return Status(1, "Supplied path is not a directory: " + path.string());
    }

    boost::filesystem::directory_iterator begin_iter(path);
    boost::filesystem::directory_iterator end_iter;
    for (; begin_iter != end_iter; begin_iter++) {
      if (!boost::filesystem::is_directory(begin_iter->path())) {
        results.push_back(begin_iter->path().string());
      }
    }

    return Status(0, "OK");
  } catch (const boost::filesystem::filesystem_error& e) {
    return Status(1, e.what());
  }
}

Status listDirectoriesInDirectory(const boost::filesystem::path& path,
                                  std::vector<std::string>& results) {
  try {
    if (!boost::filesystem::exists(path)) {
      return Status(1, "Directory not found");
    }

    auto stat = pathExists(path);
    if (!stat.ok()) {
      return stat;
    }

    stat = isDirectory(path);
    if (!stat.ok()) {
      return stat;
    }

    boost::filesystem::directory_iterator begin_iter(path);
    boost::filesystem::directory_iterator end_iter;
    for (; begin_iter != end_iter; begin_iter++) {
      if (boost::filesystem::is_directory(begin_iter->path())) {
        results.push_back(begin_iter->path().string());
      }
    }

    return Status(0, "OK");
  } catch (const boost::filesystem::filesystem_error& e) {
    return Status(1, e.what());
  }
}

/**
 * @brief Drill down recursively and list all sub files
 *
 * This functions purpose is to take a path with no wildcards
 * and it will recursively go through all files and and return
 * them in the results vector.
 *
 * @param fs_path The entire resolved path
 * @param results The vector where results will be returned
 * @param rec_depth How many recursions deep the current execution is at
 *
 * @return An instance of osquery::Status indicating the success of failure of
 * the operation
 */
Status doubleStarTraversal(const boost::filesystem::path& fs_path,
                           std::vector<std::string>& results,
                           unsigned int rec_depth) {
  if (rec_depth >= kMaxDirectoryTraversalDepth) {
    return Status(2, fs_path.string().c_str());
  }
  // List files first
  Status stat = listFilesInDirectory(fs_path, results);
  if (!stat.ok()) {
    return Status(0, "OK");
  }
  std::vector<std::string> folders;
  stat = listDirectoriesInDirectory(fs_path, folders);
  if (!stat.ok()) {
    return Status(0, "OK");
  }

  for (const auto& folder : folders) {
    boost::filesystem::path p(folder);
    if (boost::filesystem::is_symlink(p)) {
      continue;
    }
    stat = doubleStarTraversal(folder, results, rec_depth + 1);
    if (!stat.ok() && stat.getCode() == 2) {
      return stat;
    }
  }
  return Status(0, "OK");
}

/**
 * @brief Resolve the last component of a file path
 *
 * This function exists because unlike the other parts of of a file
 * path, which should only resolve to folder, a wildcard at the end
 * means to list all files in that directory, as does just listing
 * folder. Also, a double means to drill down recursively into that
 * that folder and list all sub file.
 *
 * @param fs_path The entire resolved path (except last component)
 * @param results The vector where results will be returned
 * @param components A path, split by forward slashes
 * @param rec_depth How many recursions deep the current execution is at
 *
 * @return An instance of osquery::Status indicating the success of failure of
 * the operation
 */
Status resolveLastPathComponent(const boost::filesystem::path& fs_path,
                                std::vector<std::string>& results,
                                const std::vector<std::string>& components,
                                unsigned int rec_depth) {
  // Is the last component a double star?
  if (components[components.size() - 1] == kWildcardCharacterRecursive) {
    Status stat =
        doubleStarTraversal(fs_path.parent_path(), results, rec_depth);
    return stat;
  }

  // Is the path a file
  try {
    if (boost::filesystem::is_regular_file(fs_path)) {
      results.push_back(fs_path.string());
      return Status(0, "OK");
    }
  } catch (const boost::filesystem::filesystem_error& e) {
    // This should catch permission problems
    return Status(0, "OK");
  }

  std::vector<std::string> files;
  Status stat = listFilesInDirectory(fs_path.parent_path(), files);
  if (!stat.ok()) {
    return stat;
  }

  // Is the last component a wildcard?
  if (components[components.size() - 1] == kWildcardCharacter) {
    for (const auto& file : files) {
      results.push_back(file);
    }
    return Status(0, "OK");
  }

  std::string processed_path =
      "/" +
      boost::algorithm::join(
          std::vector<std::string>(components.begin(), components.end() - 1),
          "/");

  // Is this a .*% type file match
  if (components[components.size() - 1].find(kWildcardCharacter, 1) !=
          std::string::npos &&
      components[components.size() - 1][0] != kWildcardCharacter[0]) {

    std::string prefix =
        processed_path + "/" +
        components[components.size() - 1].substr(
            0, components[components.size() - 1].find(kWildcardCharacter, 1));
    for (const auto& file : files) {
      if (file.find(prefix, 0) != 0) {
        continue;
      }
      results.push_back(file);
    }
  }

  // Is this a %(.*) type file match
  if (components[components.size() - 1][0] == kWildcardCharacter[0]) {
    std::string suffix = components[components.size() - 1].substr(1);

    for (const auto& file : files) {
      boost::filesystem::path p(file);
      std::string file_name = p.filename().string();
      size_t pos = file_name.find(suffix);
      if (pos != std::string::npos &&
          pos + suffix.length() == file_name.length()) {
        results.push_back(file);
      }
    }
    return Status(0, "OK");
  }

  // Back out if this path doesn't exist due to invalid path
  if (!(pathExists(fs_path).ok())) {
    return Status(0, "OK");
  }

  // Is the path a directory
  if (boost::filesystem::is_directory(fs_path)) {
    for (auto& file : files) {
      results.push_back(file);
    }
    return Status(0, "OK");
  }

  return Status(1, "UNKNOWN FILE TYPE");
}

/**
 * @brief List all files in a directory recursively
 *
 * This is an overloaded version of the exported `resolveFilePattern`. This
 * version is used internally to facilitate the tracking of the recursion
 * depth.
 *
 * @param results The vector where results will be returned
 * @param components A path, split by forward slashes
 * @param processed_index What index of components has been resolved so far
 * @param rec_depth How many recursions deep the current execution is at
 *
 * @return An instance of osquery::Status indicating the success of failure of
 * the operation
 */
Status resolveFilePattern(std::vector<std::string> components,
                          std::vector<std::string>& results,
                          unsigned int processed_index = 0,
                          unsigned int rec_depth = 0) {

  // Stop recursing here if we've reached out max depth
  if (rec_depth >= kMaxDirectoryTraversalDepth) {
    return Status(2, "MAX_DEPTH");
  }

  // Handle all parts of the path except last because then we want to get files,
  // not directories
  for (auto i = processed_index; i < components.size() - 1; i++) {

    // If we encounter a full recursion, that is invalid because it is not
    // the last component. So return.
    if (components[i] == kWildcardCharacterRecursive) {
      return Status(1, kWildcardCharacterRecursive + " NOT LAST COMPONENT");
    }

    // Create a vector to hold all the folders in the current folder
    // Build the path we're at out of components
    std::vector<std::string> folders;

    std::string processed_path =
        "/" +
        boost::algorithm::join(std::vector<std::string>(components.begin(),
                                                        components.begin() + i),
                               "/");
    Status stat = listDirectoriesInDirectory(processed_path, folders);
    // If we couldn't list the directories it's probably because
    // the path is invalid (or we don't have permission). Return
    // here because this branch is no good. This is not an error
    if (!stat.ok()) {
      return Status(0, "OK");
    }
    // If we just have a wildcard character then we will recurse though
    // all folders we find
    if (components[i] == kWildcardCharacter) {
      for (const auto& dir : folders) {
        boost::filesystem::path p(dir);
        components[i] = p.filename().string();
        Status stat =
            resolveFilePattern(components, results, i + 1, rec_depth + 1);
        if (!stat.ok() && stat.getCode() == 2) {
          return stat;
        }
      }
      // Our subcalls that handle processing are now complete, return
      return Status(0, "OK");

      // The case of (.*)%
    } else if (components[i].find(kWildcardCharacter, 1) != std::string::npos &&
               components[i][0] != kWildcardCharacter[0]) {
      std::string prefix =
          processed_path + "/" +
          components[i].substr(0, components[i].find(kWildcardCharacter, 1));
      for (const auto& dir : folders) {
        if (dir.find(prefix, 0) != 0) {
          continue;
        }
        boost::filesystem::path p(dir);
        components[i] = p.filename().string();
        Status stat =
            resolveFilePattern(components, results, i + 1, rec_depth + 1);
        if (!stat.ok() && stat.getCode() == 2) {
          return stat;
        }
      }
      return Status(0, "OK");
      // The case of %(.*)
    } else if (components[i][0] == kWildcardCharacter[0]) {
      std::string suffix = components[i].substr(1);
      for (const auto& dir : folders) {
        boost::filesystem::path p(dir);
        std::string folder_name = p.filename().string();
        size_t pos = folder_name.find(suffix);
        if (pos != std::string::npos &&
            pos + suffix.length() == folder_name.length()) {
          components[i] = p.filename().string();
          Status stat =
              resolveFilePattern(components, results, i + 1, rec_depth + 1);
          if (!stat.ok() && stat.getCode() == 2) {
            return stat;
          }
        }
      }
      return Status(0, "OK");
    } else {
    }
  }

  // At this point, all of our call paths have been resolved, so know we want to
  // list the files at this point or do our ** traversal
  return resolveLastPathComponent("/" + boost::algorithm::join(components, "/"),
                                  results,
                                  components,
                                  rec_depth);
}

Status resolveFilePattern(const boost::filesystem::path& fs_path,
                          std::vector<std::string>& results) {
  return resolveFilePattern(split(fs_path.string(), "/"), results);
}

Status getDirectory(const boost::filesystem::path& path,
                    boost::filesystem::path& dirpath) {
  if (!isDirectory(path).ok()) {
    dirpath = boost::filesystem::path(path).parent_path().string();
    return Status(0, "OK");
  }
  dirpath = path;
  return Status(1, "Path is a directory: " + path.string());
}

Status isDirectory(const boost::filesystem::path& path) {
  if (boost::filesystem::is_directory(path)) {
    return Status(0, "OK");
  }
  return Status(1, "Path is not a directory: " + path.string());
}
}
