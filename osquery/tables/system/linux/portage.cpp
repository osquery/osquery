/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

/**
 *  Portage support by J.O. Aho <trizt@aho.hk>
 */

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim_all.hpp>
#include <boost/utility.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

/* File paths used by portage */
const std::string kPortagePackageDir{"/var/db/pkg"};
const std::string kPortageKeywords{"/etc/portage/package.keywords"};
const std::string kPortageEtcMake{"/etc/make.conf"};
const std::string kPortageEtcPortageMake{"/etc/portage/make.conf"};
const std::string kPortageMask{"/etc/portage/package.mask"};
const std::string kPortageUnMask{"/etc/portage/package.unmask"};
const std::string kPortageUse{"/etc/portage/package.use"};
const std::string kPortageWorld{"/var/lib/portage/world"};

/* Shared functions and structs */

/**
 * @brief a non copyable container to hold data before we store it to QueryData
 */
class PortagePackage : boost::noncopyable {
 public:
  std::string package;
  std::string version;
  std::string keyword;
  std::string mask;
  std::string unmask;
  PortagePackage() {
    mask = unmask = "0";
  }
};

/**
 * @brief split a package string with version into package name and package
 * version.
 *
 * we need to split a package stirring which includes the version it affects into
 * a pair of package name (first) and package version (second).
 */
std::pair<std::string, std::string> portageSplitPackageVersion(
    const std::string& pkg_str) {
  std::string package_str = pkg_str;
  if (package_str.back() == '/') {
    package_str.pop_back();
  }

  std::pair<std::string, std::string> package = std::make_pair("", "");
  while (boost::starts_with(package_str, ">") ||
         boost::starts_with(package_str, "<") ||
         boost::starts_with(package_str, "=")) {
    if (!(package.second.length() == 0 &&
          boost::starts_with(package_str, "="))) {
      package.second += package_str.substr(0, 1);
    }
    package_str.erase(0, 1);
  }
  auto divider_pos = package_str.find('/');
  auto version_pos = package_str.find_last_of('-');
  if (version_pos != std::string::npos && version_pos > divider_pos &&
      version_pos < package_str.length() - 1 &&
      isdigit(package_str[version_pos + 1])) {
    package.second += package_str.substr(version_pos + 1);
    package_str.erase(version_pos, package_str.length() - version_pos);
  } else {
    version_pos = package_str.find_last_of('-', version_pos - 1);
    if (version_pos != std::string::npos && version_pos > divider_pos &&
        version_pos < package_str.length() - 1 &&
        isdigit(package_str[version_pos + 1])) {
      package.second += package_str.substr(version_pos + 1);
      package_str.erase(version_pos, package_str.length() - version_pos);
    }
  }
  package.first = package_str;
  return package;
}

/* Functions to fetch content for database tables */
QueryData parsePortagePackages(const std::vector<std::string>& pkg_paths,
                               const std::string& world_content) {
  QueryData results;

  // store world in a map so we can use find to see if
  // a package is in the world file
  std::unordered_map<std::string, bool> world;
  if (!world_content.empty()) {
    for (const auto& i : osquery::split(world_content, "\n")) {
      auto line = split(i);
      if (line.size() == 0 || boost::starts_with(line[0], "#")) {
        continue;
      }
      auto package = portageSplitPackageVersion(line[0]);
      world.emplace(std::make_pair(package.first, true));
    }
  }

  for (const auto& directory : pkg_paths) {
    Row r;
    std::string pkg = directory;
    pkg.erase(0, 12);

    auto package = portageSplitPackageVersion(pkg);
    r["package"] = package.first;
    r["version"] = package.second;
    r["world"] = world.end() == world.find(package.first) ? "0" : "1";

    std::string slotCont;
    if (readFile(directory + "/SLOT", slotCont).ok()) {
      boost::trim(slotCont);
      r["slot"] = slotCont;
    }

    std::string sizeCont;
    if (readFile(directory + "/SIZE", sizeCont).ok()) {
      boost::trim(sizeCont);
      r["size"] = sizeCont;
    }

    std::string eapiCont;
    if (readFile(directory + "/EAPI", eapiCont).ok()) {
      boost::trim(eapiCont);
      r["eapi"] = eapiCont;
    }

    std::string buildCont;
    if (readFile(directory + "/BUILD_TIME", buildCont).ok()) {
      boost::trim(buildCont);
      r["build_time"] = buildCont;
    }

    std::string repoCont;
    if (readFile(directory + "/repository", repoCont).ok()) {
      boost::trim(repoCont);
      r["repository"] = repoCont;
    }

    results.push_back(r);
  }

  return results;
}

QueryData parsePortageKeywordSummaryContent(const std::string& keywords,
                                            const std::string& masked,
                                            const std::string& unmasked) {
  QueryData results;
  std::unordered_map<std::string, std::unique_ptr<PortagePackage>> temp_storage;

  if (!keywords.empty()) {
    for (const auto& i : osquery::split(keywords, "\n")) {
      auto line = split(i);
      if (line.size() == 0 || boost::starts_with(line[0], "#")) {
        continue;
      }
      std::unique_ptr<PortagePackage> ppkg(new PortagePackage);
      auto package = portageSplitPackageVersion(line[0]);
      ppkg->package = package.first;
      ppkg->version = package.second;
      if (line.size() > 1) {
        ppkg->keyword = line[1];
        boost::algorithm::trim_all(ppkg->keyword);
      }
      ppkg->mask = "0";
      ppkg->unmask = "0";
      if (!boost::starts_with(ppkg->keyword, "#")) {
        temp_storage.emplace(std::make_pair(line[0], std::move(ppkg)));
      }
    }
  }

  if (!masked.empty()) {
    for (const auto& i : osquery::split(masked, "\n")) {
      auto line = split(i);
      if (line.size() == 0 || boost::starts_with(line[0], "#")) {
        continue;
      }

      std::unordered_map<std::string, std::unique_ptr<PortagePackage>>::iterator
          it = temp_storage.find(line[0]);
      if (temp_storage.end() != it) {
        it->second->mask = "1";
      } else {
        std::unique_ptr<PortagePackage> ppkg(new PortagePackage);
        auto package = portageSplitPackageVersion(line[0]);

        ppkg->package = package.first;
        ppkg->version = package.second;
        ppkg->keyword = "";
        ppkg->mask = "1";
        ppkg->unmask = "0";
        temp_storage.emplace(std::make_pair(line[0], std::move(ppkg)));
      }
    }
  }

  if (!unmasked.empty()) {
    for (const auto& i : osquery::split(unmasked, "\n")) {
      auto line = split(i);
      if (line.size() == 0 || boost::starts_with(line[0], "#")) {
        continue;
      }

      std::unordered_map<std::string, std::unique_ptr<PortagePackage>>::iterator
          it = temp_storage.find(line[0]);
      if (temp_storage.end() != it) {
        it->second->unmask = "1";
      } else {
        std::unique_ptr<PortagePackage> ppkg(new PortagePackage);
        auto package = portageSplitPackageVersion(line[0]);

        ppkg->package = package.first;
        ppkg->version = package.second;
        ppkg->keyword = "";
        ppkg->mask = "0";
        ppkg->unmask = "1";
        temp_storage.emplace(std::make_pair(line[0], std::move(ppkg)));
      }
    }
  }

  for (auto it = temp_storage.begin(); it != temp_storage.end(); ++it) {
    Row r;
    r["package"] = it->second->package;
    r["version"] = it->second->version;
    r["keyword"] = it->second->keyword;
    r["mask"] = it->second->mask;
    r["unmask"] = it->second->unmask;
    results.push_back(r);
  }
  return results;
}

QueryData parsePortageUseContent(const std::vector<std::string>& pkg_paths) {
  QueryData results;

  for (const auto& directory : pkg_paths) {
    Row r;
    std::string pkg = directory;
    pkg.erase(0, 12);

    auto package = portageSplitPackageVersion(pkg);

    std::string use_content;
    if (readFile(directory + "/USE", use_content).ok()) {
      boost::trim(use_content);
      if (!use_content.empty()) {
        for (const auto& use_flag : osquery::split(use_content, " ")) {
          r["use"] = use_flag;
          r["package"] = package.first;
          r["version"] = package.second;
          results.push_back(r);
        }
      }
    }
  }
  return results;
}

/* Functions referred from tables */
QueryData portagePackages(QueryContext& context) {
  std::string content_use;
  std::vector<std::string> pkg_paths;
  if (isDirectory(kPortagePackageDir).ok() &&
      readFile(kPortageWorld, content_use).ok() &&
      resolveFilePattern(kPortagePackageDir + "/*/*", pkg_paths, GLOB_FOLDERS)
          .ok()) {
    return parsePortagePackages(pkg_paths, content_use);
  } else {
    return {};
  }
}

QueryData genPortageUse(QueryContext& context) {
  std::vector<std::string> pkg_paths;
  if (isDirectory(kPortagePackageDir).ok() &&
      resolveFilePattern(kPortagePackageDir + "/*/*", pkg_paths, GLOB_FOLDERS)
          .ok()) {
    return parsePortageUseContent(pkg_paths);
  } else {
    return {};
  }
}

QueryData genPortageKeywordSummary(QueryContext& context) {
  std::string keywords;
  std::string masked;
  std::string unmasked;
  readFile(kPortageKeywords, keywords);
  readFile(kPortageMask, masked);
  readFile(kPortageUnMask, unmasked);

  if (!keywords.empty() || !masked.empty() || unmasked.empty()) {
    return parsePortageKeywordSummaryContent(keywords, masked, unmasked);
  } else {
    return {};
  }
}
}
}
