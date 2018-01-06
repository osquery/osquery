/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string/replace.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

static inline void parseAptUrl(const std::string& source,
                               const std::string& line,
                               QueryData& results) {
  auto comp = osquery::split(line, " ");
  if (comp.empty() || comp[0][0] == '#') {
    return;
  }

  Row r;
  r["source"] = source;
  // The source name could set [arch=ARCH].
  size_t offset = (comp[0][0] == '[') ? 1 : 0;
  r["base_uri"] = comp[offset];
  // Seek to the end of the schema.
  auto host = comp[offset].find("://");
  if (host == std::string::npos) {
    return;
  }

  std::vector<std::string> cache_file_parts;
  cache_file_parts.push_back(comp[offset].substr(host + 3));
  for (size_t i = offset + 1; i < comp.size(); i++) {
    if (comp[i][0] == '#') {
      // Stop parsing if there is a comment.
      break;
    }
    cache_file_parts.push_back(comp[i]);
  }

  // The name is the full set of components.
  r["name"] = osquery::join(cache_file_parts, " ");
  // The cache file is formatted differently.
  cache_file_parts.insert(cache_file_parts.begin() + 1, "dists");
  // Remove the 'section'.
  cache_file_parts.pop_back();
  auto cache_file = osquery::join(cache_file_parts, "_");
  boost::replace_all(cache_file, "/", "_");

  std::vector<std::string> cache_files;
  resolveFilePattern("/var/lib/apt/lists/" + cache_file + "_%Release",
                     cache_files,
                     GLOB_FILES);
  if (cache_files.empty()) {
    return;
  }

  std::string content;
  if (!readFile(cache_files[0], content)) {
    return;
  }

  for (const auto& header : osquery::split(content, "\n")) {
    if (header.empty()) {
      continue;
    }
    if (header == "-----BEGIN PGP SIGNATURE-----") {
      // We have entered the file hashes section.
      break;
    }
    auto fields = osquery::split(header, ":");
    if (fields.size() != 2) {
      continue;
    }

    if (fields[0] == "Codename") {
      r["release"] = fields[1];
    } else if (fields[0] == "Version") {
      r["version"] = fields[1];
    } else if (fields[0] == "Origin") {
      r["maintainer"] = fields[1];
    } else if (fields[0] == "Components") {
      r["components"] = fields[1];
    } else if (fields[0] == "Architectures") {
      r["architectures"] = fields[1];
    }
  }

  results.push_back(r);
}

static void parseAptSource(const std::string& source, QueryData& results) {
  std::string content;
  if (!readFile(source, content)) {
    return;
  }

  for (const auto& line : osquery::split(content, "\n")) {
    // Skip comments.
    if (line.size() == 0 || line[0] == '#') {
      continue;
    }

    // Only look for deb names (not deb-src).
    if (line.find("deb ") != 0) {
      continue;
    }
    parseAptUrl(source, line.substr(4), results);
  }
}

QueryData genAptSrcs(QueryContext& context) {
  QueryData results;

  // We are going to read a few files.
  auto dropper = DropPrivileges::get();
  dropper->dropTo("nobody");

  // Expect the APT home to be /etc/apt.
  std::vector<std::string> sources;
  sources.push_back("/etc/apt/sources.list");
  if (!resolveFilePattern(
          "/etc/apt/sources.list.d/%.list", sources, GLOB_FILES)) {
    VLOG(1) << "Cannot resolve apt sources";
    return results;
  }

  for (const auto& source : sources) {
    VLOG(1) << source;
    parseAptSource(source, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
