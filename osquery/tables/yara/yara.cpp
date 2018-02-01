/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/status.h>
#include <osquery/tables.h>

#include "osquery/tables/yara/yara_utils.h"

#ifdef CONCAT
#undef CONCAT
#endif
#include <yara.h>

#define DECLARE_TABLE_IMPLEMENTATION_yara
#include <generated/tables/tbl_yara_defs.hpp>

namespace osquery {
namespace tables {

void doYARAScan(YR_RULES* rules,
                const std::string& path,
                QueryData& results,
                const std::string& group,
                const std::string& sigfile) {
  Row r;

  // These are default values, to be updated in YARACallback.
  r["count"] = INTEGER(0);
  r["matches"] = std::string("");
  r["strings"] = std::string("");
  r["tags"] = std::string("");

  // This could use target_path instead to be consistent with yara_events.
  r["path"] = path;
  r["sig_group"] = std::string(group);
  r["sigfile"] = std::string(sigfile);

  // Perform the scan, using the static YARA subscriber callback.
  int result = yr_rules_scan_file(
      rules, path.c_str(), SCAN_FLAGS_FAST_MODE, YARACallback, (void*)&r, 0);
  if (result == ERROR_SUCCESS) {
    results.push_back(std::move(r));
  }
}

QueryData genYara(QueryContext& context) {
  QueryData results;

  // Must specify a path constraint and at least one of sig_group or sigfile.
  auto groups = context.constraints["sig_group"].getAll(EQUALS);
  auto sigfiles = context.constraints["sigfile"].getAll(EQUALS);
  if (groups.size() == 0 && sigfiles.size() == 0) {
    return results;
  }

  // This could be abstracted into a common "get rules for group" function.
  auto parser = Config::getParser("yara");
  if (parser == nullptr || parser.get() == nullptr) {
    LOG(ERROR) << "YARA config parser plugin has no pointer";
    return results;
  }

  std::shared_ptr<YARAConfigParserPlugin> yaraParser = nullptr;
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

  // Collect all paths specified too.
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_FILES | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            // Check that each resolved path is readable.
            if (isReadable(resolved)) {
              paths.insert(resolved);
            }
          }
        }
        return status;
      }));

  // Compile all sigfiles into a map.
  for (const auto& file : sigfiles) {
    // Check if this "ad-hoc" signature file has not been used/compiled.
    if (rules.count(file) == 0) {
      // If this is a relative path append the default yara search path.
      auto path = (file[0] != '/') ? kYARAHome : "";
      path += file;

      YR_RULES* tmp_rules = nullptr;
      auto status = compileSingleFile(path, &tmp_rules);
      if (!status.ok()) {
        VLOG(1) << "YARA compile error: " << status.toString();
        continue;
      }
      // Cache the compiled rules by setting the unique signature file path
      // as the lookup name. Additional signature file uses will skip the
      // compile step and be added as rule groups.
      rules[file] = tmp_rules;
    }
    // Assemble an "ad-hoc" group using the signature file path as the name.
    groups.insert(file);
  }

  // Scan every path pair.
  for (const auto& path : paths) {
    // Scan using the signature groups.
    for (const auto& group : groups) {
      if (rules.count(group) > 0) {
        doYARAScan(rules[group], path.c_str(), results, group, group);
      }
    }
  }

  return results;
}
}
}
