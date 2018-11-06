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

namespace osquery {
namespace tables {

void doYARAScan(YR_RULES* rules,
                const std::string& path,
                QueryData& results,
                const std::string& group, bool is_adhoc_string = false) {
  Row r;

  // These are default values, to be updated in YARACallback.
  r["count"] = INTEGER(0);
  r["matches"] = std::string("");
  r["strings"] = std::string("");
  r["tags"] = std::string("");

  // This could use target_path instead to be consistent with yara_events.
  r["path"] = path;
  if (is_adhoc_string) {
    r["adhoc_rules"] = group;
    r["sig_group"] = "";
    r["sigfile"] = "";
  } else {
    r["sig_group"] = std::string(group);
    r["sigfile"] = std::string(group);
    r["adhoc_rules"] = "";
  }

  // Perform the scan, using the static YARA subscriber callback.
  int result = yr_rules_scan_file(
      rules, path.c_str(), SCAN_FLAGS_FAST_MODE, YARACallback, (void*)&r, 0);
  if (result == ERROR_SUCCESS) {
    results.push_back(std::move(r));
  } else {
    VLOG(1) << "yr_rules_scan_file returned" << result;
  }
}

QueryData genYara(QueryContext& context) {
  QueryData results;

  // Must specify a path constraint and at least one of sig_group or sigfile.
  auto groups = context.constraints["sig_group"].getAll(EQUALS);
  auto adhoc_rules_strings = context.constraints["adhoc_rules"].getAll(EQUALS);
  auto sigfiles = context.constraints["sigfile"].getAll(EQUALS);
  if (groups.size() == 0 && sigfiles.size() == 0 && adhoc_rules_strings.size() == 0) {
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
  } catch (const std::bad_cast& ) {
    LOG(ERROR) << "Error casting yara config parser plugin";
    return results;
  }
  if (yaraParser == nullptr || yaraParser.get() == nullptr) {
    LOG(ERROR) << "YARA config parser plugin has no pointer";
    return results;
  }
  auto& rules = yaraParser->rules();
  auto& adhoc_rules = yaraParser->rules();

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
  int i = -1;
  for (const auto& file : sigfiles) {
    i++;
    if (rules.count(file) > 0) {
      LOG(WARNING) << "YARA sigfile already specified in query:" << file;
      continue;
    }

    std::string ruleName = file;
    YR_RULES* tmp_rules = nullptr;

    // If this is a relative path append the default yara search path.
    auto path = (file[0] != '/') ? kYARAHome : "";
    path += file;

    auto status = compileSingleFile(path, &tmp_rules);
    if (!status.ok()) {
      VLOG(1) << "YARA compile error: " << status.toString();
      continue;
    }

    if (tmp_rules == nullptr) {
      VLOG(1) << "No rules after successful compile:" << file;
      continue;
    }

    // Cache the compiled rules by setting the unique signature file path
    // as the lookup name. Additional signature file uses will skip the
    // compile step and be added as rule groups.
    rules[ruleName] = tmp_rules;

    // Assemble an "ad-hoc" group using the signature file path as the name.
    groups.insert(ruleName);
  }

  // Compile all sigfiles into a map.
  i = -1;
  for (const auto& rules_string : adhoc_rules_strings) {
    i++;
    if (rules.count(rules_string) > 0) {
      LOG(WARNING) << "YARA adhoc_rules already specified in query:" << rules_string;
      continue;
    }

    YR_RULES* tmp_rules = nullptr;

    auto status = compileRulesFromString(rules_string, &tmp_rules);
    if (!status.ok()) {
      VLOG(1) << "YARA compile error: " << status.toString();
      continue;
    }

    if (tmp_rules == nullptr) {
      VLOG(1) << "No rules after successful compile:" << rules_string;
      continue;
    }

    // Cache the compiled rules by setting the unique signature file path
    // as the lookup name. Additional signature file uses will skip the
    // compile step and be added as rule groups.
    adhoc_rules[rules_string] = tmp_rules;
  }

  // Scan every path pair.
  for (const auto& path : paths) {
    // Scan using the signature groups.
    for (const auto& group : groups) {
      if (rules.count(group) > 0) {
        VLOG(2) << "scanning group:" << group << " path:" << path;
        doYARAScan(rules[group], path.c_str(), results, group);
      }
    }
    for (auto it=adhoc_rules.begin(); it != adhoc_rules.end(); it++) {
      const auto &rule_string = it->first;
      VLOG(2) << "scanning rules:" << rule_string << " path:" << path;
      doYARAScan(it->second, path.c_str(), results, rule_string, true);
    }
  }

  while(adhoc_rules.size() > 0) {
    const std::string key = adhoc_rules.begin()->first;
    yr_rules_destroy(adhoc_rules[key]);
    adhoc_rules.erase(key);
  }

  while(rules.size() > 0) {
    const std::string key = rules.begin()->first;
    yr_rules_destroy(rules[key]);
    rules.erase(key);
  }

  return results;
}

} // namespace tables
} // namespace osquery
