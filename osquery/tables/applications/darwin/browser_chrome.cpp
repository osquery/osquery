/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/property_tree/json_parser.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

/// Each home directory will include custom extensions.
#define kChromePath "/Library/Application Support/Google/Chrome/Default/"
#define kChromeExtensionsPath "Extensions/"
#define kChromeManifestFile "/manifest.json"

const std::map<std::string, std::string> kChromeExtensionKeys = {
    {"version", "version"},
    {"name", "name"},
    {"description", "description"},
    {"default_locale", "locale"},
    {"update_url", "update_url"},
    {"author", "author"},
    {"background.persistent", "persistent"},
};

void genChromeExtension(const std::string& path, QueryData& results) {
  std::string json_data;
  if (!readFile(path + kChromeManifestFile, json_data).ok()) {
    VLOG(1) << "Could not read file: " << path + kChromeManifestFile;
    return;
  }

  // Read the extensions data into a JSON blob, then property tree.
  pt::ptree tree;
  std::stringstream json_stream;
  json_stream << json_data;
  try {
    pt::read_json(json_stream, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    VLOG(1) << "Could not parse JSON from: " << path + kChromeManifestFile;
    return;
  }

  Row r;
  // Most of the keys are in the top-level JSON dictionary.
  for (const auto& it : kChromeExtensionKeys) {
    try {
      r[it.second] = tree.get<std::string>(it.first);
    } catch (const pt::ptree_error& e) {
      r[it.second] = "";
    }

    // Convert JSON bool-types to an integer.
    if (r[it.second] == "true") {
      r[it.second] = INTEGER(1);
    } else if (r[it.second] == "false") {
      r[it.second] = INTEGER(0);
    }
  }

  // Set the default persistence setting to false
  if (r.at("persistent") == "") {
    r["persistent"] = INTEGER(0);
  }

  r["identifier"] = fs::path(path).parent_path().leaf().string();
  r["path"] = path;
  results.push_back(r);
}

QueryData genChromeExtensions(QueryContext& context) {
  QueryData results;

  auto homes = osquery::getHomeDirectories();
  for (const auto& home : homes) {
    // For each user, enumerate all of their Chrome profiles.
    std::vector<std::string> extensions;
    fs::path extension_path = home / (kChromePath kChromeExtensionsPath);
    if (!listDirectoriesInDirectory(extension_path, extensions).ok()) {
      continue;
    }

    // Generate an addons list from their extensions JSON.
    for (const auto& extension : extensions) {
      std::vector<std::string> versions;
      if (!listDirectoriesInDirectory(extension, versions).ok()) {
        continue;
      }

      // Extensions use /<ID>/<VERSION>/manifest.json.
      for (const auto& version : versions) {
        genChromeExtension(version, results);
      }
    }
  }

  return results;
}
}
}
