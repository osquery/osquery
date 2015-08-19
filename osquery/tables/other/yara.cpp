/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/status.h>

#include "osquery/tables/other/yara_utils.h"

#ifdef CONCAT
#undef CONCAT
#endif
#include <yara.h>

namespace osquery {
namespace tables {

Status doYARAScan(YR_RULES* rules,
                  const std::string& path,
                  const std::string& pattern,
                  QueryData& results,
                  const std::string& group,
                  const std::string& sigfile) {
  Row r;

  // These are default values, to be updated in YARACallback.
  r["count"] = INTEGER(0);
  r["matches"] = std::string("");
  r["strings"] = std::string("");
  r["tags"] = std::string("");

  // XXX: use target_path instead to be consistent with yara_events?
  r["path"] = path;

  r["pattern"] = pattern;

  r["sig_group"] = std::string(group);
  r["sigfile"] = std::string(sigfile);

  int result = yr_rules_scan_file(rules,
                                  path.c_str(),
                                  SCAN_FLAGS_FAST_MODE,
                                  YARACallback,
                                  (void*)&r,
                                  0);

  if (result != ERROR_SUCCESS) {
    return Status(1, "Scan error (" + std::to_string(result) + ")");
  }

  results.push_back(r);
  return Status(0, "OK");
}

QueryData genYara(QueryContext& context) {
  QueryData results;

  auto paths = context.constraints["path"].getAll(EQUALS);
  auto patterns = context.constraints["pattern"].getAll(EQUALS);
  auto groups = context.constraints["sig_group"].getAll(EQUALS);
  auto sigfiles = context.constraints["sigfile"].getAll(EQUALS);

  // Must specify a path constraint and at least one of sig_group or sigfile.
  if (groups.size() == 0 && sigfiles.size() == 0) {
    return results;
  }

  // XXX: Abstract this into a common "get rules for group" function.
  auto parser = Config::getParser("yara");
  if (parser == nullptr || parser.get() == nullptr) {
    LOG(ERROR) << "YARA config parser plugin has no pointer";
    return results;
  }

  std::shared_ptr<YARAConfigParserPlugin> yaraParser;
  try {
    yaraParser = std::dynamic_pointer_cast<YARAConfigParserPlugin>(parser);
  } catch (const std::bad_cast& e) {
    LOG(ERROR) << "Error casting yara config parser plugin";
    return results;
  }
  if (yaraParser == nullptr || yaraParser.get() == nullptr) {
    LOG(ERROR) << "YARA config parser plugin has no pointer";
    return results;
  }

  auto& rules = yaraParser->rules();

  // Store resolved paths in a vector of pairs.
  // Each pair has the first element as the path to scan and the second
  // element as the pattern which generated it.
  std::vector<std::pair<std::string, std::string> > path_pairs;

  // Expand patterns and push onto path_pairs.
  for (const auto& pattern : patterns) {
    std::vector<std::string> expanded_patterns;
    auto status = resolveFilePattern(pattern, expanded_patterns);
    if (!status.ok()) {
      VLOG(1) << "Could not expand pattern properly: " << status.toString();
      return results;
    }

    for (const auto& resolved : expanded_patterns) {
      if (!isReadable(resolved)) {
        continue;
      }
      path_pairs.push_back(make_pair(resolved, pattern));
    }
  }

  // Collect all paths specified too.
  for (const auto& path_string : paths) {
    if (!isReadable(path_string)) {
      continue;
    }
    path_pairs.push_back(make_pair(path_string, ""));
  }

  // Compile all sigfiles into a map.
  for (const auto& file : sigfiles) {
    // Check if this on-demand sigfile has not been used/compiled.
    if (rules.count(file) == 0) {
      auto path = (file[0] != '/') ? std::string("/etc/osquery/yara/") : "";
      path += file;

      YR_RULES* tmp_rules = nullptr;
      auto status = compileSingleFile(path, &tmp_rules);
      if (!status.ok()) {
        VLOG(1) << "YARA error: " << status.toString();
      } else {
        rules[file] = tmp_rules;
        groups.insert(file);
      }
    }
  }

  // Scan every path pair.
  for (const auto& path_pair : path_pairs) {
    // Scan using siggroups.
    for (const auto& group : groups) {
      if (rules.count(group) == 0) {
        continue;
      }

      VLOG(1) << "Scanning with group: " << group;
      auto status = doYARAScan(rules[group],
                               path_pair.first.c_str(),
                               path_pair.second,
                               results,
                               group,
                               group);
      if (!status.ok()) {
        VLOG(1) << "YARA error: " << status.toString();
      }
    }
  }

  return results;
}
}
}
