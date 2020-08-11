/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <boost/filesystem.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/json/json.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::vector<std::string> kPackageKeys{"name", "version", "description"};

const std::string kLinuxNodeModulesPath{"/usr/lib/"};

void genPackageResults(const std::string& directory,
                       QueryData& results,
                       Logger& logger) {
  std::vector<std::string> packages;
  resolveFilePattern(directory + "/node_modules/%/package.json", packages);

  for (const auto& package_path : packages) {
    std::string json;
    if (!readFile(package_path, json).ok()) {
      logger.log(google::GLOG_WARNING,
                 "Could not read package JSON: " + package_path);
      continue;
    }

    auto doc = JSON::newObject();
    if (!doc.fromString(json) || !doc.doc().IsObject()) {
      logger.log(google::GLOG_WARNING,
                 "Could not parse JSON from: " + package_path);
      continue;
    }

    Row r;
    for (const auto& key : kPackageKeys) {
      if (doc.doc().HasMember(key)) {
        const auto& value = doc.doc()[key];
        // npm has a schema for package.json, but it is loosely enforced. Some
        // keys may be missing, so populate the columns we can
        r[key] = (value.IsString()) ? value.GetString() : "";
      }
    }

    // Manually get nested key (Author name)
    if (doc.doc().HasMember("author")) {
      const auto& author = doc.doc()["author"];
      if (author.IsString()) {
          r["author"] = author.GetString();
      } else if (author.IsObject()) {
        if (author.HasMember("name")) {
          const auto& author_name = author["name"];
          r["author"] = (author_name.IsString()) ? author_name.GetString() : "";
        }
      }
    }

    // Manually get license to support deprecated licence schema.
    // In the current schema it is a string, but in previous versions it is a
    // dictionary with url and type
    if (doc.doc().HasMember("license")) {
      const auto& license = doc.doc()["license"];
      if (license.IsString()) {
        // Current license schema is just a top level string
        r["license"] = license.GetString();
      } else {
        // If its not a string, is it a dict with 'url' ?
        if (license.HasMember("url")) {
          const auto& license_url = license["url"];
          if (license_url.IsString()) {
            // Fallback to displaying deprecated licence url
            r["license"] = license_url.GetString();
          }
        }
      }
    }

    r["path"] = package_path;
    r["directory"] = directory;
    r["pid_with_namespace"] = "0";

    results.push_back(r);
  }
}

QueryData genNPMPackagesImpl(QueryContext& context, Logger& logger) {
  QueryData results;

  std::set<std::string> search_directories = {kLinuxNodeModulesPath};
  if (context.constraints.count("directory") > 0 &&
      context.constraints.at("directory").exists(EQUALS)) {
    search_directories = context.constraints["directory"].getAll(EQUALS);
  }

  for (const auto& directory : search_directories) {
    genPackageResults(directory, results, logger);
  }

  return results;
}

QueryData genNPMPackages(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "npm_packages", genNPMPackagesImpl);
  } else {
    GLOGLogger logger;
    return genNPMPackagesImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
