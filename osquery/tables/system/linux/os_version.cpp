/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <map>
#include <string>

#include <boost/algorithm/string/find.hpp>
#include <boost/algorithm/string/trim_all.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/xpressive/xpressive.hpp>
#include <osquery/filesystem.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace xp = boost::xpressive;

namespace osquery {
namespace tables {

const std::string kOSRelease {"/etc/os-release"};
const std::string kRedhatRelease {"/etc/redhat-release"};
const std::string kGentooRelease {"/etc/gentoo-release"};

const std::map<std::string, std::string> kOSReleaseColumns = {
    {"NAME", "name"},
    {"VERSION", "version"},
    {"BUILD_ID", "build"},
    {"ID", "platform"},
    {"ID_LIKE", "platform_like"},
    {"VERSION_CODENAME", "codename"},
    {"VERSION_ID", "_id"},
};

QueryData genOSRelease(Row& r) {
  // This will parse /etc/os-version according to the systemd manual.
  std::string content;
  if (!readFile(kOSRelease, content).ok()) {
    return {r};
  }

  for (const auto& line : osquery::split(content, "\n")) {
    auto fields = osquery::split(line, "=", 1);
    if (fields.size() != 2) {
      continue;
    }

    auto column = std::ref(kOSReleaseColumns.at("VERSION_CODENAME"));
    if (kOSReleaseColumns.count(fields[0]) != 0) {
      column = std::ref(kOSReleaseColumns.at(fields[0]));
    } else if (fields[0].find("CODENAME") == std::string::npos) {
      // Some distros may attach/invent their own CODENAME field.
      continue;
    }

    r[column] = std::move(fields[1]);
    if (!r.at(column).empty() && r.at(column)[0] == '"') {
      // This is quote-enclosed string, make it pretty!
      r[column] = r[column].substr(1, r.at(column).size() - 2);
    }

    if (column.get() == "_id") {
      auto parts = osquery::split(r.at(column), ".", 2);
      switch (parts.size()) {
      case 3:
        r["patch"] = parts[2];
      case 2:
        r["minor"] = parts[1];
      case 1:
        r["major"] = parts[0];
        break;
      }
    }
  }

  return {r};
}

QueryData genOSVersion(QueryContext& context) {
  Row r;

  // Set defaults if we cannot determine the version.
  r["name"] = "Unknown";
  r["major"] = "0";
  r["minor"] = "0";
  r["patch"] = "0";
  r["platform"] = "posix";

  if (isReadable(kOSRelease)) {
    boost::system::error_code ec;
    // Funtoo has an empty os-release file.
    if (boost::filesystem::file_size(kOSRelease, ec) > 0) {
      return genOSRelease(r);
    }
  }

  std::string content;
  if (readFile(kRedhatRelease, content).ok()) {
    r["platform"] = "rhel";
    r["platform_like"] = "rhel";
  } else if (readFile(kGentooRelease, content).ok()) {
    r["platform"] = "gentoo";
    r["platform_like"] = "gentoo";
  } else {
    return {r};
  }

  boost::algorithm::trim_all(content);

  // This is an older version of a Redhat-based OS.
  auto rx = xp::sregex::compile(
      "(?P<name>[\\w+\\s]+) .* "
      "(?P<major>[0-9]+)\\.(?P<minor>[0-9]+)\\.?(?P<patch>\\w+)?");
  xp::smatch matches;
  for (const auto& line : osquery::split(content, "\n")) {
    if (xp::regex_search(line, matches, rx)) {
      r["major"] = INTEGER(matches["major"]);
      r["minor"] = INTEGER(matches["minor"]);
      r["patch"] =
          (matches["patch"].length() > 0) ? INTEGER(matches["patch"]) : "0";
      r["name"] = matches["name"];
      break;
    }
  }

  r["version"] = content;

  // No build name.
  r["build"] = "";

  if (r["platform"] == "") {
    // Try to detect CentOS from the name. CentOS6 does not have all of the
    // keys we expect above that platform is typically extracted from.
    if (!boost::algorithm::ifind_first(r["name"], "centos").empty()) {
      r["platform"] = "centos";
    }
  }

  return {r};
}
}
}
