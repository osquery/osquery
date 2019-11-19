/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <boost/algorithm/string/replace.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/tables/system/posix/apt_sources.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/system/system.h>

namespace osquery {
namespace tables {

Status parseAptSourceLine(const std::string& line, AptSource& apt_source) {
  auto comp = osquery::split(line, " ");
  if (comp.empty() || comp[0][0] == '#') {
    return Status::failure("Cannot parse comment");
  }

  // The source name could set [arch=ARCH].
  size_t offset = (comp.size() > 1 && comp[0][0] == '[') ? 1 : 0;
  // Seek to the end of the schema.
  auto host = comp[offset].find("://");
  if (host == std::string::npos) {
    return Status::failure("Cannot find protocol");
  }

  apt_source.base_uri = comp[offset];
  apt_source.cache_file.push_back(comp[offset].substr(host + 3));
  if (apt_source.cache_file[0].empty()) {
    return Status::failure("Cache file is empty");
  }

  // Cannot have trailing slashes
  while (apt_source.cache_file.back().back() == '/') {
    apt_source.cache_file.back().pop_back();
  }

  bool use_dists = true;
  for (size_t i = offset + 1; i < comp.size(); i++) {
    if (comp[i][0] == '#') {
      // Stop parsing if there is a comment.
      break;
    }
    auto parts = osquery::split(comp[i], "/");
    use_dists = parts.size() == 1;
    apt_source.cache_file.insert(
        apt_source.cache_file.end(), parts.begin(), parts.end());
  }

  // Construct the source 'name'.
  apt_source.name = osquery::join(apt_source.cache_file, " ");

  if (use_dists) {
    // The cache file is formatted differently.
    apt_source.cache_file.insert(apt_source.cache_file.begin() + 1, "dists");
    // Remove the 'section'.
    apt_source.cache_file.pop_back();
  }

  return Status::success();
}

std::string getCacheFilename(const std::vector<std::string>& cache_file) {
  // The name is the full set of components.
  auto filename = osquery::join(cache_file, "_");
  boost::replace_all(filename, "/", "_");
  return filename;
}

void genAptUrl(const std::string& source,
               const std::string& line,
               QueryData& results) {
  AptSource apt_source;
  if (!parseAptSourceLine(line, apt_source).ok()) {
    return;
  }

  Row r;
  r["source"] = source;
  r["base_uri"] = std::move(apt_source.base_uri);
  r["name"] = std::move(apt_source.name);

  std::vector<std::string> cache_files;
  auto cache_filename = getCacheFilename(apt_source.cache_file);
  resolveFilePattern("/var/lib/apt/lists/" + cache_filename + "_%Release",
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

static void genAptSource(const std::string& source, QueryData& results) {
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
    genAptUrl(source, line.substr(4), results);
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
    VLOG(1) << "Cannot resolve apt sources /etc/apt/sources.list.d";
    return results;
  }

  for (const auto& source : sources) {
    genAptSource(source, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
