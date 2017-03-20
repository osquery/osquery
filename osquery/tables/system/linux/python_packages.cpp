/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#include <string>
#include <fstream>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>

namespace osquery {
namespace tables {

const std::string python_path = "/usr/local/lib/python2.7/dist-packages/";

void genPackage(std::string path, Row &r) {
  std::ifstream fd (path, std::ios::in | std::ios::binary);
  
  if (fd.eof() || fd.fail()) {
    VLOG(1) << "Empty or malformed file";
    return;
  }

  // loop breaks when last relevant field is read
  while (!fd.eof()) {
    std::string line;
    std::getline(fd, line, '\n');
    std::vector<std::string> fields;
    boost::split(fields, line, boost::is_any_of(":"));

    for (auto& f : fields) {
      boost::trim(f);
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

QueryData genPythonPackages(QueryContext &context) {
  QueryData results;
  
  std::vector<std::string> directories;
  if (listDirectoriesInDirectory(python_path, directories).ok()) {
    for (const auto& directory : directories) {
      Row r;
      std::string path;
      if (directory.find(".dist-info") != std::string::npos) {
	path = directory + "/METADATA";
	genPackage(path, r);
	results.push_back(r);     
      } else if (directory.find(".egg-info") != std::string::npos) {
	path = directory + "/PKG-INFO";
	genPackage(path, r);	
	results.push_back(r);     
      }       
    }
  }

  return results;
}

}
}
