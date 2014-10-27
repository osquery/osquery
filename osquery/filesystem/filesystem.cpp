// Copyright 2004-present Facebook. All Rights Reserved.

#include <fstream>
#include <sstream>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "osquery/filesystem.h"

using osquery::Status;

namespace pt = boost::property_tree;

namespace osquery {

Status readFile(const std::string& path, std::string& content) {
  if (!boost::filesystem::exists(path)) {
    return Status(1, "File not found");
  }

  int statusCode = 0;
  std::string statusMessage = "OK";
  char* buffer;

  std::ifstream file_h(path);
  if (file_h) {
    file_h.seekg(0, file_h.end);
    int len = file_h.tellg();
    file_h.seekg(0, file_h.beg);
    buffer = new char[len];
    file_h.read(buffer, len);
    if (!file_h) {
      statusCode = 1;
      statusMessage = "Could not read file";
      goto cleanup_buffer;
    }
    content.assign(buffer, len);
  } else {
    statusCode = 1;
    statusMessage = "Could not open file for reading";
    goto cleanup;
  }

cleanup_buffer:
  delete[] buffer;
cleanup:
  if (file_h) {
    file_h.close();
  }
  return Status(statusCode, statusMessage);
}

Status isWritable(const std::string& path) {
  if (!pathExists(path).ok()) {
    return Status(1, "Path does not exists.");
  }

  if (access(path.c_str(), W_OK) == 0) {
    return Status(0, "OK");
  }
  return Status(1, "Path is not writable.");
}

Status pathExists(const std::string& path) {
  if (path.length() == 0) {
    return Status(0, "-1");
  }

  // A tri-state determination of presence
  if (!boost::filesystem::exists(path)) {
    return Status(0, "0");
  }
  return Status(0, "1");
}

Status listFilesInDirectory(const std::string& path,
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
  }
  catch (const boost::filesystem::filesystem_error& e) {
    return Status(1, e.what());
  }
}

Status getDirectory(const std::string& path, std::string& dirpath) {
  if (!isDirectory(path).ok()) {
    dirpath = boost::filesystem::path(path).parent_path().string();
    return Status(0, "OK");
  }
  dirpath = path;
  return Status(1, "Path is a directory");
}

Status isDirectory(const std::string& path) {
  if (boost::filesystem::is_directory(path)) {
    return Status(0, "OK");
  }
  return Status(1, "Path is not a directory");
}

Status parseTomcatUserConfigFromDisk(
    const std::string& path,
    std::vector<std::pair<std::string, std::string>>& credentials) {
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
    std::vector<std::pair<std::string, std::string>>& credentials) {
  std::stringstream ss;
  ss << content;
  pt::ptree tree;
  try {
    pt::xml_parser::read_xml(ss, tree);
  }
  catch (const pt::xml_parser_error& e) {
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
        }
        catch (const std::exception& e) {
          LOG(ERROR)
              << "An error occured parsing the tomcat users xml: " << e.what();
          return Status(1, e.what());
        }
      }
    }
  }
  catch (const std::exception& e) {
    LOG(ERROR) << "An error occured while trying to access the tomcat-users"
               << " key in the XML content: " << e.what();
    return Status(1, e.what());
  }
  return Status(0, "OK");
}
}
