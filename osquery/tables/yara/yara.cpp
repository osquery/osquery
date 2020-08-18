/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>
#include <thread>

#ifdef LINUX
#include <malloc.h>
#endif

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/hashing/hashing.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/status/status.h>

#include "osquery/tables/yara/yara_utils.h"

#ifdef CONCAT
#undef CONCAT
#endif
#include <yara.h>

namespace osquery {

// After a large scan of many files, the memory allocation could be
// substantial.  free() may not return it to operating system, but
// rather keep it around in anticipation that app will reallocate.
// Call malloc_trim() on linux to try to convince it to release.
#ifdef LINUX
FLAG(bool,
     yara_malloc_trim,
     true,
     "Call malloc_trim() after YARA scans (linux)");
#endif

FLAG(uint32,
     yara_delay,
     50,
     "Time in ms to sleep after scan of each file (default 50) to reduce "
     "memory spikes");

FLAG(bool,
     enable_yara_table_extension,
     false,
     "Enable yara table extension to pass sigrule with query ");

namespace tables {

typedef enum { YC_NONE = 0, YC_GROUP, YC_FILE, YC_RULE } YaraScanType;

typedef std::set<std::pair<YaraScanType, std::string>> YaraScanContext;

static inline std::string hashStr(const std::string& str, YaraScanType yc) {
  switch (yc) {
  case YC_RULE:
    return "rule_" +
           hashFromBuffer(HASH_TYPE_SHA256, str.c_str(), str.length());
  default:
    return str;
  }
};

// Get yara config parser
static std::shared_ptr<YARAConfigParserPlugin> getYaraParser(void) {
  auto parser = Config::getParser("yara");
  if (parser == nullptr || parser.get() == nullptr) {
    LOG(ERROR) << "YARA config parser plugin has no pointer";
    return nullptr;
  }

  std::shared_ptr<YARAConfigParserPlugin> yaraParser = nullptr;
  try {
    yaraParser = std::dynamic_pointer_cast<YARAConfigParserPlugin>(parser);
  } catch (const std::bad_cast& e) {
    LOG(ERROR) << "Error casting yara config parser plugin";
    return nullptr;
  }

  return yaraParser;
}

void doYARAScan(YR_RULES* rules,
                const std::string& path,
                QueryData& results,
                YaraScanType yc,
                const std::string& sigfile) {
  Row r;

  // These are default values, to be updated in YARACallback.
  r["count"] = INTEGER(0);
  r["matches"] = std::string("");
  r["strings"] = std::string("");
  r["tags"] = std::string("");

  // This could use target_path instead to be consistent with yara_events.
  r["path"] = path;
  r["sig_group"] = yc == YC_GROUP ? std::string(sigfile) : std::string("");
  r["sigfile"] = yc == YC_FILE ? std::string(sigfile) : std::string("");
  r["sigrule"] = yc == YC_RULE ? std::string(sigfile) : std::string("");

  // Perform the scan, using the static YARA subscriber callback.
  int result = yr_rules_scan_file(
      rules, path.c_str(), SCAN_FLAGS_FAST_MODE, YARACallback, (void*)&r, 0);
  if (result == ERROR_SUCCESS) {
    results.push_back(std::move(r));
  }
}

Status genYaraRuleFromFile(QueryContext& queryContext,
                           YaraScanContext& scanContext) {
  auto yaraParser = getYaraParser();
  if (yaraParser == nullptr || yaraParser.get() == nullptr) {
    return Status::failure("YARA config parser plugin has no pointer");
  }

  auto& rules = yaraParser->rules();
  auto sigfiles = queryContext.constraints["sigfile"].getAll(EQUALS);

  for (const auto& file : sigfiles) {
    // Check if this "ad-hoc" signature file has not been used/compiled.
    if (rules.count(hashStr(file, YC_FILE)) == 0) {
      // If this is a relative path append the default yara search path.
      auto path = (file[0] != '/') ? kYARAHome : "";
      path += file;

      YR_RULES* tmp_rules = nullptr;
      auto status = compileSingleFile(path, &tmp_rules);
      if (!status.ok()) {
        LOG(WARNING) << "YARA compile error: " << status.toString();
        continue;
      }
      // Cache the compiled rules by setting the unique signature file path
      // as the lookup name. Additional signature file uses will skip the
      // compile step and be added to the scan context
      rules[hashStr(file, YC_FILE)] = tmp_rules;
    }

    scanContext.insert(std::make_pair(YC_FILE, file));
  }

  return Status::success();
}

Status genYaraRuleFromString(QueryContext& queryContext,
                             YaraScanContext& scanContext) {
  auto yaraParser = getYaraParser();
  if (yaraParser == nullptr || yaraParser.get() == nullptr) {
    return Status::failure("YARA config parser plugin has no pointer");
  }

  auto& rules = yaraParser->rules();
  auto sigrules = queryContext.constraints["sigrule"].getAll(EQUALS);

  // Compile signature string and add them to the scan context
  for (const auto& rule_string : sigrules) {
    if (rules.count(hashStr(rule_string, YC_RULE)) == 0) {
      YR_RULES* tmp_rules = nullptr;

      auto status = compileFromString(rule_string, &tmp_rules);
      if (!status.ok()) {
        LOG(WARNING) << "YARA rule : " << rule_string << status.toString();
        continue;
      }

      rules[hashStr(rule_string, YC_RULE)] = tmp_rules;
    }
    // Add rule string to the scan context set
    scanContext.insert(std::make_pair(YC_RULE, rule_string));
  }

  return Status::success();
}

QueryData genYara(QueryContext& context) {
  QueryData results;

  // Must specify a path constraint and at least one of sig_group, sigfile, or
  // sigrule
  auto groups = context.constraints["sig_group"].getAll(EQUALS);
  auto sigfiles = context.constraints["sigfile"].getAll(EQUALS);
  auto sigrules = context.constraints["sigrule"].getAll(EQUALS);
  if (groups.empty() && sigfiles.empty() && sigrules.empty()) {
    return results;
  }

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
            struct stat sb;
            if (0 != stat(resolved.c_str(), &sb)) {
              continue; // failed to stat the file
            }

            // Check that each resolved path is readable.
            if (isReadable(resolved) &&
                !yaraShouldSkipFile(resolved, sb.st_mode)) {
              paths.insert(resolved);
            }
          }
        }
        return status;
      }));

  auto yr_init = yaraInitilize();
  if (!yr_init.ok()) {
    LOG(WARNING) << yr_init.toString();
    return results;
  }

  YaraScanContext scanContext;

  // Add signature groups to the scan context
  for (const auto& group : groups) {
    scanContext.insert(std::make_pair(YC_GROUP, group));
  }

  // Compile signature files and add them to the scan context
  auto file_status = genYaraRuleFromFile(context, scanContext);
  if (!file_status.ok()) {
    return results;
  }

  if (FLAGS_enable_yara_table_extension) {
    auto rule_status = genYaraRuleFromString(context, scanContext);
    if (!rule_status.ok()) {
      return results;
    }
  }

  auto yaraParser = getYaraParser();
  if (yaraParser == nullptr || yaraParser.get() == nullptr) {
    return results;
  }

  // Scan every path pair with the yara rules
  auto& rules = yaraParser->rules();
  for (const auto& path : paths) {
    for (const auto& sign : scanContext) {
      if (rules.count(hashStr(sign.second, sign.first)) > 0) {
        doYARAScan(rules[hashStr(sign.second, sign.first)],
                   path.c_str(),
                   results,
                   sign.first,
                   sign.second);

        // sleep between each file to help smooth out malloc spikes
        std::this_thread::sleep_for(
            std::chrono::milliseconds(FLAGS_yara_delay));
      }
    }
  }

  // Rule string is hashed before adding to the cache. There are
  // possibilities of collision when arbitrary queries are executed
  // with distributed API. Clear the hash string from the cache
  for (const auto& sign : scanContext) {
    if (sign.first == YC_RULE) {
      auto it = rules.find(hashStr(sign.second, sign.first));
      if (it != rules.end()) {
        rules.erase(hashStr(sign.second, sign.first));
      }
    }
  }

  // Clean-up after finish scanning; If yr_initialize is called
  // more than once it will decrease the reference counter and return
  auto yr_fini = yaraFinalize();
  if (!yr_fini.ok()) {
    LOG(WARNING) << yr_fini.toString();
  }

#ifdef LINUX
  if (osquery::FLAGS_yara_malloc_trim) {
    malloc_trim(0);
  }
#endif

  return results;
}
} // namespace tables
} // namespace osquery
