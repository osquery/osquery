// Copyright 2004-present Facebook. All Rights Reserved.

#include <ctime>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include "osquery/database.h"

using std::string;
using boost::lexical_cast;

namespace osquery {
namespace tables {

const std::string kXattrQuarantine = "com.apple.quarantine";

QueryData genQuarantine() {
  QueryData results;

  auto it = boost::filesystem::recursive_directory_iterator(boost::filesystem::path("/"));
  boost::filesystem::recursive_directory_iterator end;

  while (it != end) {
    boost::filesystem::path path = *it;
    try {
      Row r;
      std::vector<std::string> values;
      std::string filePathQuotes = boost::lexical_cast<std::string>(path);
      std::string filePath = filePathQuotes.substr(1, filePathQuotes.length() - 2);

      int bufferLength = getxattr(filePath.c_str(), kXattrQuarantine.c_str(), NULL, 0, 0, 0);
      if (bufferLength > 0) {
	char *value = (char *) malloc(sizeof(char *) * bufferLength);
	getxattr(filePath.c_str(), kXattrQuarantine.c_str(), value, bufferLength, 0, 0);

	boost::split(values, value, boost::is_any_of(";"));
	boost::trim(values[2]);

	r["path"] = filePath;
	r["creator"] = values[2];

	results.push_back(r);
	free(value);
      }
    } catch (...) {
      LOG(ERROR) << "Couldn't handle file " << boost::lexical_cast<std::string>(*it);
    }
    try {
      ++it;
    } catch (const std::exception &ex) {
      LOG(WARNING) << "Permissions error on " << boost::lexical_cast<std::string>(*it);
      it.no_push(); 
    }
  }

  return results;
}
}
}
