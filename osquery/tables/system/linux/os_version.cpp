/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

#include <boost/regex.hpp>

#include <osquery/filesystem.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#ifdef CENTOS
const std::string kLinuxOSRelease = "/etc/redhat-release";
#define kLinuxOSRegex "CentOS release ([0-9]+).([0-9]+)"
#else
const std::string kLinuxOSRelease = "/etc/os-release";
#define kLinuxOSRegex "VERSION=\"([0-9]+)\\.([0-9]+)[\\.]{0,1}([0-9]+)?"
#endif

namespace osquery {
namespace tables {

QueryData genOSVersion(QueryContext& context) {
  std::string content;
  if (!readFile(kLinuxOSRelease, content).ok()) {
    return {};
  }

  std::vector<std::string> version = {"0", "0", "0"};
  boost::regex rx(kLinuxOSRegex);
  boost::smatch matches;
  for (const auto& line : osquery::split(content, "\n")) {
    if (boost::regex_search(line, matches, rx)) {
      // Push the matches in reverse order.
      version[0] = matches[1];
      version[1] = matches[2];
      if (matches.size() == 4) {
        // Patch is optional for Ubuntu and not used for CentOS.
        version[2] = matches[3];
      }
      break;
    }
  }

  Row r;
  if (version.size() == 3) {
    r["major"] = INTEGER(version[0]);
    r["minor"] = INTEGER(version[1]);
    r["patch"] = INTEGER(version[2]);
  }
  return {r};
}
}
}
