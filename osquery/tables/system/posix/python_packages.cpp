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

#include <osquery/core/conversions.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>
#include <osquery/tables.h>


namespace osquery {
namespace tables {

const int kNumFields = 2;
const std::set<std::string> kPythonPath = {
  "/usr/local/lib/python2.7/", "/usr/lib/python2.7/dist-packages",
};


// checks if given set of paths are sub-path of one another
int checkOverlap() {

  for (const auto& path : kPythonPath) {
    int count = 0;
    for (const auto& key : kPythonPath ) {
      if (count > 1)
	return -1;
      else if (key.find(path) != std::string::npos)
	count += 1;
    }

  }
  return 1;
}

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
  
  if (checkOverlap() == -1) {
    VLOG(1) << "Overlapping directories in provided set of paths"; 
    return results;
  }

  for (const auto& key : kPythonPath) {
    std::vector<std::string> directories;
    if (listDirectoriesInDirectory(key, directories, true).ok()) {    
      for (const auto& directory : directories) {
	if (isDirectory(directory).ok()) {
	    Row r;
	    std::string path;
	    if (directory.find(".dist-info") != std::string::npos) {
	      path = directory + "/METADATA";
	      genPackage(path, r);
	      r["path"] = directory;
	      results.push_back(r);     
	    } else if (directory.find(".egg-info") != std::string::npos) {
	      path = directory + "/PKG-INFO";
	      genPackage(path, r);
	      r["path"] = directory;
	      results.push_back(r);     
	    }       
	}
      }
    }
  }
  return results;
}

}
}
