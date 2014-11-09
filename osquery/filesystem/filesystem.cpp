// Copyright 2004-present Facebook. All Rights Reserved.

#include <exception>
#include <sstream>

#include <fcntl.h>
#include <sys/stat.h>

#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <glog/logging.h>

#include "osquery/filesystem.h"

using osquery::Status;

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
    return Status(1, "Could not create file");
  }

  // If the file existed with different permissions before our open
  // they must be restricted.
  if (chmod(path.c_str(), permissions) != 0) {
    // Could not change the file to the requested permissions.
    return Status(1, "Failed to change permissions");
  }

  auto bytes = write(output_fd, content.c_str(), content.size());
  if (bytes != content.size()) {
    close(output_fd);
    return Status(1, "Failed to write contents");
  }

  close(output_fd);
  return Status(0, "OK");
}

Status readFile(const boost::filesystem::path& path, std::string& content) {
  auto path_exists = pathExists(path);
  if (!path_exists.ok()) {
    return path_exists;
  }

  int statusCode = 0;
  std::string statusMessage = "OK";
  std::unique_ptr<char> buffer;

  fs::ifstream file_h(path);
  if (file_h) {
    file_h.seekg(0, file_h.end);
    int len = file_h.tellg();
    file_h.seekg(0, file_h.beg);
    buffer = std::unique_ptr<char>(new char[len]);
    file_h.read(buffer.get(), len);
    if (!file_h) {
      statusCode = 1;
      statusMessage = "Could not read file";
    }
    content.assign(buffer.get(), len);
  } else {
    statusCode = 1;
    statusMessage = "Could not open file for reading";
    
    if (file_h) {
      file_h.close();
    }
  }
  return Status(statusCode, statusMessage);
}

Status isWritable(const boost::filesystem::path& path) {
  auto path_exists = pathExists(path);
  if (!path_exists.ok()) {
    return path_exists;
  }

  if (access(path.c_str(), W_OK) == 0) {
    return Status(0, "OK");
  }
  return Status(1, "Path is not writable.");
}

Status isReadable(const boost::filesystem::path& path) {
  auto path_exists = pathExists(path);
  if (!path_exists.ok()) {
    return path_exists;
  }

  if (access(path.c_str(), R_OK) == 0) {
    return Status(0, "OK");
  }
  return Status(1, "Path is not readable.");
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
  }
  catch (boost::filesystem::filesystem_error e) {
    return Status(1, e.what());
  }
  return Status(0, "1");
}

Status listFilesInDirectory(const boost::filesystem::path& path,
                            std::vector<std::string>& results) {
  try {
    if (!boost::filesystem::exists(path)) {
      return Status(1, "Directory not found");
    }

    if (!boost::filesystem::is_directory(path)) {
      return Status(1, "Supplied path is not a directory");
    }

    boost::filesystem::directory_iterator begin_iter(path);
    boost::filesystem::directory_iterator end_iter;
    for (; begin_iter != end_iter; begin_iter++) {
      results.push_back(begin_iter->path().string());
    }

    return Status(0, "OK");
  } catch (const boost::filesystem::filesystem_error& e) {
    return Status(1, e.what());
  }
}

Status getDirectory(const boost::filesystem::path& path,
                    boost::filesystem::path& dirpath) {
  if (!isDirectory(path).ok()) {
    dirpath = boost::filesystem::path(path).parent_path().string();
    return Status(0, "OK");
  }
  dirpath = path;
  return Status(1, "Path is a directory");
}

Status isDirectory(const boost::filesystem::path& path) {
  if (boost::filesystem::is_directory(path)) {
    return Status(0, "OK");
  }
  return Status(1, "Path is not a directory");
}

Status parseTomcatUserConfigFromDisk(
    const boost::filesystem::path& path,
    std::vector<std::pair<std::string, std::string> >& credentials) {
  std::string content;
  auto s = readFile(path, content);
  if (s.ok()) {
    return parseTomcatUserConfig(content, credentials);
  } else {
    return s;
  }
}

Status parseTomcatUserConfig(
    const std::string& content,
    std::vector<std::pair<std::string, std::string> >& credentials) {
  std::stringstream ss;
  ss << content;
  pt::ptree tree;
  try {
    pt::xml_parser::read_xml(ss, tree);
  } catch (const pt::xml_parser_error& e) {
    return Status(1, e.what());
  }
  try {
    for (const auto& i : tree.get_child("tomcat-users")) {
      if (i.first == "user") {
        try {
          std::pair<std::string, std::string> user;
          user.first = i.second.get<std::string>("<xmlattr>.username");
          user.second = i.second.get<std::string>("<xmlattr>.password");
          credentials.push_back(user);
        } catch (const std::exception& e) {
          LOG(ERROR)
              << "An error occurred parsing the tomcat users xml: " << e.what();
          return Status(1, e.what());
        }
      }
    }
  } catch (const std::exception& e) {
    LOG(ERROR) << "An error occurred while trying to access the tomcat-users"
               << " key in the XML content: " << e.what();
    return Status(1, e.what());
  }
  return Status(0, "OK");
}
}
