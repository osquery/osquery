// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/filesystem.h"

#include <iostream>
#include <fstream>
#include <sstream>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <gflags/gflags.h>
#include <glog/logging.h>

using osquery::core::Status;

namespace osquery { namespace fs {

Status readFile(const std::string& path, std::string& content) {
  if (!boost::filesystem::exists(path)) {
    return Status(1, "File not found");
  }

  std::ifstream file_h(path);
  if (file_h) {
     file_h.seekg (0, file_h.end);
     int len = file_h.tellg();
     file_h.seekg (0, file_h.beg);
     char *buffer = new char [len];
     file_h.read(buffer, len);
     if (!file_h) {
      return Status(1, "Could not entire file");
     }
     content = std::string(buffer);
  } else {
    return Status(1, "Could not open file for reading");
  }

  return Status(0, "OK");
}

}}
