/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cerrno>
#include <sys/utsname.h>

#include <map>
#include <regex>
#include <string>

#include <boost/algorithm/string/find.hpp>
#include <boost/algorithm/string/trim_all.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

const std::string kOSRelease = "/etc/os-release";
const std::string kRedhatRelease = "/etc/redhat-release";
const std::string kGentooRelease = "/etc/gentoo-release";

const std::map<std::string, std::string> kOSReleaseColumns = {
    {"NAME", "name"},
    {"VERSION", "version"},
    {"BUILD_ID", "build"},
    {"ID", "platform"},
    {"ID_LIKE", "platform_like"},
    {"VERSION_CODENAME", "codename"},
    {"VERSION_ID", "_id"},
};

void genOSRelease(Row& r) {
  // This will parse /etc/os-version according to the systemd manual.
  std::string content;
  if (!readFile(kOSRelease, content).ok()) {
    return;
  }

  for (const auto& line : osquery::split(content, "\n")) {
    auto fields = osquery::split(line, '=', 1);
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
      auto parts = osquery::split(r.at(column), '.', 2);
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

  return;
}

QueryData genOSVersionImpl(QueryContext& context, Logger& logger) {
  Row r;

  // Set defaults if we cannot determine the version.
  r["name"] = "Unknown";
  r["major"] = "0";
  r["minor"] = "0";
  r["patch"] = "0";
  r["platform"] = "posix";
  r["pid_with_namespace"] = "0";

  if (isReadable(kOSRelease)) {
    boost::system::error_code ec;
    // Funtoo has an empty os-release file.
    if (boost::filesystem::file_size(kOSRelease, ec) > 0) {
      genOSRelease(r);
    }
  }

  struct utsname uname_buf {};

  if (uname(&uname_buf) == 0) {
    r["arch"] = TEXT(uname_buf.machine);
  } else {
    LOG(INFO) << "Failed to determine the OS architecture, error " << errno;
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
  auto rx = std::regex("([\\w+\\s]+) .* ([0-9]+)\\.([0-9]+)\\.?(\\w+)?");
  std::smatch matches;
  for (const auto& line : osquery::split(content, "\n")) {
    if (std::regex_search(line, matches, rx)) {
      r["name"] = matches[1];
      r["major"] = matches[2];
      r["minor"] = matches[3];
      r["patch"] = matches[4];
      if (r["patch"].empty()) {
        r["patch"] = "0";
      }
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

QueryData genOSVersion(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "osversion", genOSVersionImpl);
  } else {
    GLOGLogger logger;
    return genOSVersionImpl(context, logger);
  }
}

} // namespace tables
} // namespace osquery
