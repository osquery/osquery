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

#include <boost/algorithm/string/trim.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>
#include <osquery/tables.h>
#include <osquery/core/conversions.h>

namespace osquery {
namespace tables {

const std::string kPythonPath = "/usr/local/lib/python2.7/";
const int kNumFields = 2;
const std::set<std::string> kPath = {
"/usr/local/lib/python2.7/"
};


void genPackage(std::string path, Row &r) {
  std::ifstream fd (path, std::ios::in | std::ios::binary);
  
  if (fd.eof() || fd.fail()) {
    VLOG(1) << "Empty or malformed file";
    return;
  }

  while (!fd.eof()) {
    std::string line;
    std::getline(fd, line, '\n');
    auto fields = split(line, ":");

    for (auto& f : fields) {
      boost::trim(f);
    }

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

QueryData genPythonPackages(QueryContext &context) {
  QueryData results;
  
  std::vector<std::string> directories;
  if (listDirectoriesInDirectory(kPythonPath, directories).ok()) {
    for (const auto& directory : directories) {
      std::vector<std::string> subdirectories;
      if (isDirectory(directory).ok()) {
	if (listDirectoriesInDirectory(directory, subdirectories).ok()) {
	  for (const auto& subdirectory : subdirectories) {
	    Row r;
	    std::string path;
	    if (subdirectory.find(".dist-info") != std::string::npos) {
	      path = subdirectory + "/METADATA";
	      genPackage(path, r);
	      results.push_back(r);     
	    } else if (subdirectory.find(".egg-info") != std::string::npos) {
	      path = subdirectory + "/PKG-INFO";
	      genPackage(path, r);	
	      results.push_back(r);     
	    }       
	  }
	}
      }
    }
  }
  return results;
}

}
}
