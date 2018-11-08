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

namespace fs = boost::filesystem;

#ifdef CONCAT
#undef CONCAT
#endif
#include <yara.h>

typedef enum { YC_NONE = 0, YC_GROUP, YC_FILE, YC_ADHOC } YaraContextType;

struct YaraRuleContext {
  std::string value_; // group name, file_name, or rules string
  YaraContextType type_;
  YR_RULES* compiled_rules_;

  YaraRuleContext(std::string group_file_or_content,
                  YaraContextType ct,
                  YR_RULES* compiled_rules)
      : value_(group_file_or_content),
        type_(ct),
        compiled_rules_(compiled_rules) {}

  ~YaraRuleContext() {
    // do not free up rules owned by config parser (YC_GROUP)
    if (YC_GROUP != type_ && compiled_rules_ != nullptr) {
      yr_rules_destroy(compiled_rules_);
      compiled_rules_ = nullptr;
    }
  }
};
typedef std::shared_ptr<YaraRuleContext> SPYaraRuleContext;

namespace osquery {
namespace tables {

/*
 * Calls yr_rules_scan_file(), adds row to results().
 * @returns true if match was made, false otherwise.
 */
bool doYARAScan(SPYaraRuleContext yrc,
                const std::string& path,
                QueryData& results) {
  Row r;

  // These are default values, to be updated in YARACallback.
  r["count"] = "0";
  r["matches"] = "";
  r["strings"] = "";
  r["tags"] = "";

  // Perform the scan, using the static YARA subscriber callback.
  int result = yr_rules_scan_file(yrc->compiled_rules_,
                                  path.c_str(),
                                  SCAN_FLAGS_FAST_MODE,
                                  YARACallback,
                                  (void*)&r,
                                  0);

  if (result == ERROR_SUCCESS) {
    // This could use target_path instead to be consistent with yara_events.
    r["path"] = path;
    r["adhoc_rules"] = (YC_ADHOC == yrc->type_ ? yrc->value_ : "");
    r["sig_group"] = (YC_GROUP == yrc->type_ ? yrc->value_ : "");
    r["sigfile"] = (YC_FILE == yrc->type_ ? yrc->value_ : "");

    results.push_back(std::move(r));

    return (r["count"] != "0");

  } else {
    LOG(INFO) << "yr_rules_scan_file returned" << result;
  }
  return false;
}

static void expandFSPathConstraints(QueryContext& context,
                                    const std::string& path_column_name,
                                    std::set<std::string>& paths) {
  context.expandConstraints(
      path_column_name,
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_FILES | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));
}

static inline bool contains(const std::map<std::string, std::string>& m,
                            std::string val) {
  return (m.count(val) > 0);
}

/*
 * The YARAConfigParserPlugin will get invoked during configuration process,
 * and compile any YARA rules in the config.  If a query specifies a
 * sig_group, then we need to look through the configured rules and get
 * the details.
 *
 * On return, 'dest' will contain a
 */
static void get_group_rules_from_config(
    std::vector<SPYaraRuleContext>& dest,
    const std::set<std::string> group_names) {
  if (group_names.empty()) {
    return;
  }

  auto parser = Config::getParser("yara");
  if (parser == nullptr || parser.get() == nullptr) {
    LOG(ERROR) << "YARA config parser plugin has no pointer";
    return;
  }

  std::shared_ptr<YARAConfigParserPlugin> yaraParser = nullptr;
  try {
    yaraParser = std::dynamic_pointer_cast<YARAConfigParserPlugin>(parser);
  } catch (const std::bad_cast&) {
    LOG(ERROR) << "Error casting yara config parser plugin";
    return;
  }
  if (yaraParser == nullptr || yaraParser.get() == nullptr) {
    LOG(ERROR) << "YARA config parser plugin has no pointer";
    return;
  }

  // TODO: no locking on yaraParser->rules.
  //       is it possible for config (e.g. tls) update during a query?

  for (auto& group_name : group_names) {
    auto& rules_map = yaraParser->rules();
    const auto& fit = rules_map.find(group_name);
    if (fit == rules_map.end()) {
      // no such group defined
      LOG(WARNING) << "Specified group not in config:" << group_name;
    } else {
      dest.push_back(
          std::make_shared<YaraRuleContext>(group_name, YC_GROUP, fit->second));
    }
  }
}

/*
 * Compiles YARA rules file(s) and adds entry for each to dest.
 */
static void make_sigfile_rules(std::vector<SPYaraRuleContext>& dest,
                               const std::set<std::string> sigfiles) {
  auto encountered = std::map<std::string, std::string>();

  if (sigfiles.empty()) {
    return;
  }

  for (const auto& file : sigfiles) {
    if (contains(encountered, file)) {
      LOG(WARNING) << "YARA sigfile already specified in query:" << file;
      continue;
    }
    encountered[file] = file;

    YR_RULES* tmp_rules = nullptr;

    fs::path fsp = fs::path(file);
    if (!fsp.is_absolute()) {
      fsp = fs::path(kYARAHome) / fsp;
    }
    std::string path = fsp.string();

    if (!pathExists(fs::path(path))) {
      LOG(WARNING) << "specified sigfile not present:" << path;
      continue;
    }

    if (!isReadable(path)) {
      VLOG(1) << "YARA sigfile is not readable by process:" << path;
      continue;
    }

    auto status = compileSingleFile(path, &tmp_rules);
    if (!status.ok()) {
      VLOG(1) << "YARA compile error: " << status.toString();
      continue;
    }

    if (tmp_rules == nullptr) {
      VLOG(1) << "No rules after successful compile:" << file;
      continue;
    }

    dest.push_back(std::make_shared<YaraRuleContext>(file, YC_FILE, tmp_rules));
  }
}

/*
 * Compiles YARA rules string(s) and adds entry for each to dest.
 */
static void make_adhoc_rules(std::vector<SPYaraRuleContext>& dest,
                             const std::set<std::string> rules_strings) {
  auto encountered = std::map<std::string, std::string>();

  for (const auto& yara_string : rules_strings) {
    if (contains(encountered, yara_string)) {
      LOG(WARNING) << "YARA adhoc_rules already specified in query:"
                   << yara_string;
      continue;
    }
    encountered[yara_string] = "";

    YR_RULES* tmp_rules = nullptr;

    auto status = compileRulesFromString(yara_string, &tmp_rules);
    if (!status.ok()) {
      VLOG(1) << "YARA compile error: " << status.toString();
      continue;
    }

    if (tmp_rules == nullptr) {
      VLOG(1) << "No rules after successful compile:" << yara_string;
      continue;
    }

    dest.push_back(
        std::make_shared<YaraRuleContext>(yara_string, YC_ADHOC, tmp_rules));
  }
}

QueryData genYara(QueryContext& context) {
  QueryData results;

  // Must specify a path constraint and at least one of sig_group or sigfile.
  auto groups = context.constraints["sig_group"].getAll(EQUALS);
  auto adhoc_rules_strings = context.constraints["adhoc_rules"].getAll(EQUALS);
  auto sigfiles = context.constraints["sigfile"].getAll(EQUALS);

  if (groups.size() == 0 && sigfiles.size() == 0 &&
      adhoc_rules_strings.size() == 0) {
    LOG(WARNING)
        << "Need to supply a sig_group, sigfile, or adhoc_rules string";
    return results;
  }

  auto yara_contexts = std::vector<SPYaraRuleContext>();

  get_group_rules_from_config(yara_contexts, groups);
  make_sigfile_rules(yara_contexts, sigfiles);
  make_adhoc_rules(yara_contexts, adhoc_rules_strings);

  if (yara_contexts.size() == 0) {
    LOG(INFO) << "Unable to get specified YARA rules, returning empty results";
    return results;
  }

  // Collect all paths.  works with LIKE and % patterns as well
  auto paths = context.constraints["path"].getAll(EQUALS);
  expandFSPathConstraints(context, "path", paths);

  // Scan every path pair.
  for (const auto& path : paths) {
    for (const auto& yrc : yara_contexts) {
      if (doYARAScan(yrc, path.c_str(), results)) {
        // once a rule matches, no need to run the rest
        break;
      }
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
