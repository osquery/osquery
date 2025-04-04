/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <boost/algorithm/string/compare.hpp>
#include <boost/algorithm/string/regex.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/regex/v5/regex_fwd.hpp>
#include <filesystem>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/linux/apt_sources.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/status/status.h>
#include <osquery/utils/system/system.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

Status parseAptSourceLine(const std::string& input_line,
                          AptSource& apt_source) {
  // attempts to follow conventions in this doc
  // http://manpages.ubuntu.com/manpages/xenial/man5/sources.list.5.html

  // Remove everything after # from the line for comments
  auto comment_pos = input_line.find("#");
  std::string line;
  if (comment_pos != std::string::npos) {
    line = input_line.substr(0, comment_pos);
  } else {
    line = input_line;
  }

  // Only look for deb names (not deb-src).
  auto deb_pos = line.find("deb ");
  if (deb_pos == std::string::npos) {
    return Status::failure("No deb prefix");
  }
  line = line.substr(deb_pos + 4); // for "deb " length

  // Split on whitespace
  // additional leading whitespace will get clobbered by split
  auto tokens = osquery::split(line, " ");
  if (tokens.empty()) {
    return Status::failure("Empty line");
  }
  if (tokens.size() < 2) {
    return Status::failure("not enough tokens specified");
  }

  size_t offset = 0;

  // The source name could set [arch=ARCH option2=something ].
  if (tokens[offset][0] == '[') {
    // Seek to the end of the options
    for (size_t i = offset; i < tokens.size(); i++) {
      if (tokens[i].find("]") != std::string::npos) {
        offset = i;
        break;
      }
    }
    // go to the next token after the close of options ']'
    offset++;
  }
  if (offset >= tokens.size()) {
    return Status::failure("incomplete line no suite");
  }

  auto host = tokens[offset].find("://");
  if (host == std::string::npos) {
    return Status::failure("Cannot find protocol");
  }

  apt_source.base_uri = tokens[offset];
  // Cannot have trailing slashes
  while (apt_source.base_uri.back() == '/') {
    apt_source.base_uri.pop_back();
  }

  // go on to parse the suite
  offset++;
  if (offset >= tokens.size()) {
    return Status::failure("incomplete line no suite");
  }
  std::string suite = tokens[offset];

  // get the target of the uri for the name
  if (apt_source.base_uri.size() < host + 3) {
    return Status::failure("empty uri");
  }
  apt_source.name = apt_source.base_uri.substr(host + 3); // remove "://"
  // include target uri in cache name
  apt_source.cache_file.push_back(apt_source.name);

  // Construct the source 'name' from uri and suite.
  apt_source.name += ' ' + suite;

  auto suite_parts = osquery::split(suite, "/");
  if (suite_parts.size() == 1) { // this means it is a dists format
    apt_source.cache_file.push_back(suite);
    apt_source.cache_file.insert(apt_source.cache_file.begin() + 1, "dists");
  } else {
    apt_source.cache_file.insert(
        apt_source.cache_file.end(), suite_parts.begin(), suite_parts.end());
  }

  return Status::success();
}

std::string getCacheFilename(const std::vector<std::string>& cache_file) {
  // The name is the full set of components.
  auto filename = osquery::join(cache_file, "_");
  boost::replace_all(filename, "/", "_");
  return filename;
}

void aptSourceToRow(const std::string& source,
                    const AptSource& apt_source,
                    QueryData& results,
                    Logger& logger) {
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
  auto s = readFile(cache_files[0], content);
  if (!s.ok()) {
    logger.log(google::GLOG_WARNING, s.getMessage());
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
  r["pid_with_namespace"] = "0";
  results.push_back(r);
}

void genAptUrl(const std::string& source,
               const std::string& line,
               QueryData& results,
               Logger& logger) {
  AptSource apt_source;
  if (!parseAptSourceLine(line, apt_source).ok()) {
    return;
  }

  aptSourceToRow(source, apt_source, results, logger);
}

static void genAptSource(const std::string& source,
                         QueryData& results,
                         Logger& logger) {
  std::string content;

  auto s = readFile(source, content);
  if (!s.ok()) {
    logger.log(google::GLOG_WARNING, s.getMessage());
    return;
  }

  for (const auto& line : osquery::split(content, "\n")) {
    // Skip empty lines
    if (line.empty()) {
      continue;
    }
    genAptUrl(source, line, results, logger);
  }
}

Status parseDeb822Block(const std::string& input_block,
                        std::vector<AptSource>& apt_sources) {
  std::vector<std::string> uris;
  std::vector<std::string> suites;

  for (const auto& input_line : osquery::split(input_block, "\n")) {
    // Skip empty lines
    if (input_line.empty()) {
      continue;
    }

    // Remove everything after # from the line for comments
    auto comment_pos = input_line.find("#");
    std::string line;
    if (comment_pos != std::string::npos) {
      line = input_line.substr(0, comment_pos);
    } else {
      line = input_line;
    }

    auto colon_pos = line.find(":");
    if (colon_pos == std::string::npos) {
      continue;
    }

    auto key = line.substr(0, colon_pos);
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
      return std::tolower(c);
    });
    auto value = line.substr(colon_pos + 1, std::string::npos);
    boost::trim(value);

    if (value.empty()) {
      continue;
    }

    if (key == "types") {
      auto types = osquery::split(value);
      if (std::find(types.begin(), types.end(), "deb") == types.end()) {
        return Status::failure("not a deb type repo");
      }
    }

    if (key == "enabled" && value != "on") {
      return Status::success();
    }

    if (key == "uris") {
      for (auto& uri : osquery::split(value)) {
        if (uri.find("://") == std::string::npos) {
          continue;
        }
        // Cannot have trailing slashes
        while (uri.back() == '/') {
          uri.pop_back();
        }
        uris.push_back(uri);
      }
    }

    if (key == "suites") {
      for (const auto& suite : osquery::split(value)) {
        suites.push_back(suite);
      }
    }
  }

  if (uris.size() == 0) {
    return Status::failure("missing valid URIs");
  }

  if (suites.size() == 0) {
    return Status::failure("missing Suites");
  }

  for (const auto& uri : uris) {
    // All URLs should have protocol, checked earlier
    auto proto_end = uri.find("://");
    auto name = uri.substr(proto_end + 3);
    for (const auto& suite : suites) {
      auto suite_parts = osquery::split(suite, "/");
      AptSource apt_source;

      apt_source.base_uri = uri;
      apt_source.name = name + ' ' + suite;
      apt_source.cache_file.push_back(name);

      if (suite_parts.size() == 1) {
        apt_source.cache_file.push_back("dists");
        apt_source.cache_file.push_back(suite);
      } else {
        apt_source.cache_file.insert(apt_source.cache_file.end(),
                                     suite_parts.begin(),
                                     suite_parts.end());
      }

      apt_sources.push_back(apt_source);
    }
  }

  return Status::success();
}

void genDeb822Block(const std::string& source,
                    const std::string& block,
                    QueryData& results,
                    Logger& logger) {
  std::vector<AptSource> apt_sources;
  auto status = parseDeb822Block(block, apt_sources);

  if (!status.ok()) {
    logger.vlog(1,
                "failed to parse DEB822 block in " + source + ": " +
                    status.getMessage());
  }

  for (const auto& apt_source : apt_sources) {
    aptSourceToRow(source, apt_source, results, logger);
  }
}

static void genDeb822Source(const std::string& source,
                            QueryData& results,
                            Logger& logger) {
  std::string content;

  auto s = readFile(source, content);
  if (!s.ok()) {
    logger.log(google::GLOG_WARNING, s.getMessage());
    return;
  }

  std::vector<std::string> blocks;
  boost::algorithm::split_regex(blocks, content, boost::regex("\n\n"));
  for (const auto& block : blocks) {
    // Skip empty lines
    if (block.empty()) {
      continue;
    }
    genDeb822Block(source, block, results, logger);
  }
}

QueryData genAptSrcsImpl(QueryContext& context, Logger& logger) {
  QueryData results;

  // We are going to read a few files.
  auto dropper = DropPrivileges::get();
  dropper->dropTo("nobody");

  // Expect the APT home to be /etc/apt.
  std::vector<std::string> source_lists;
  if (pathExists("/etc/apt/sources.list")) {
    source_lists.push_back("/etc/apt/sources.list");
  }
  if (!resolveFilePattern(
          "/etc/apt/sources.list.d/%.list", source_lists, GLOB_FILES)) {
    logger.vlog(1, "Cannot resolve apt sources /etc/apt/sources.list.d");
    return results;
  }

  for (const auto& source : source_lists) {
    genAptSource(source, results, logger);
  }

  std::vector<std::string> source_deb822;
  if (!resolveFilePattern(
          "/etc/apt/sources.list.d/%.sources", source_deb822, GLOB_FILES)) {
    logger.vlog(1, "Cannot resolve apt sources /etc/apt/sources.list.d");
    return results;
  }

  for (const auto& source : source_deb822) {
    genDeb822Source(source, results, logger);
  }

  return results;
}

QueryData genAptSrcs(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "apt_sources", genAptSrcsImpl);
  } else {
    GLOGLogger logger;
    return genAptSrcsImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
