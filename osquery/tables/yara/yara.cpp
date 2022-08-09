/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/remote/http_client.h>
#include <osquery/remote/transports/tls.h>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <regex>
#include <thread>

#ifdef LINUX
#include <malloc.h>
#endif

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/hashing/hashing.h>
#include <osquery/logger/logger.h>
#include <osquery/remote/uri.h>
#include <osquery/tables/yara/yara_utils.h>
#include <osquery/utils/status/status.h>
#include <osquery/worker/system/memory.h>

#ifdef CONCAT
#undef CONCAT
#endif

#include <yara.h>

namespace osquery {

#ifdef LINUX
HIDDEN_FLAG(bool,
            yara_malloc_trim,
            true,
            "Deprecated in favor of malloc_trim_threshold.");
#endif

FLAG(uint32,
     yara_delay,
     50,
     "Time in ms to sleep after scan of each file (default 50) to reduce "
     "memory spikes");

HIDDEN_FLAG(bool,
            enable_yara_string,
            false,
            "Enable returning matched YARA strings. The strings are set to "
            "private if rules are passed with sigrule");

namespace tables {

using YaraRuleSet = std::set<std::string>;

typedef enum { YC_NONE = 0, YC_GROUP, YC_FILE, YC_RULE, YC_URL } YaraRuleType;

using YARAConfigParser = std::shared_ptr<YARAConfigParserPlugin>;

using YaraScanContext = std::set<std::pair<YaraRuleType, std::string>>;

// Check if the YARAConfigParser is nullptr
static inline bool isNull(std::shared_ptr<ConfigParserPlugin> parser) {
  return (parser == nullptr) || (parser.get() == nullptr);
}

static inline std::string hashStr(const std::string& str, YaraRuleType yc) {
  switch (yc) {
  case YC_RULE:
    return "rule_" +
           hashFromBuffer(HASH_TYPE_SHA256, str.c_str(), str.length());
  default:
    return str;
  }
};

// Get the yara configuration parser
static YARAConfigParser getYaraParser(void) {
  auto parser = Config::getParser("yara");
  if (isNull(parser)) {
    LOG(ERROR) << "YARA config parser plugin not found";
    return nullptr;
  }

  YARAConfigParser yaraParser = nullptr;
  try {
    yaraParser = std::dynamic_pointer_cast<YARAConfigParserPlugin>(parser);
  } catch (const std::bad_cast&) {
    LOG(ERROR) << "Cannot cast YARA config parser plugin";
    return nullptr;
  }

  return yaraParser;
}

bool isRuleUrlAllowed(std::set<std::string> signature_set, std::string url) {
  Uri test_uri(url);
  for (const auto& sig : signature_set) {
    Uri sig_uri(sig);

    // The uri scheme, host and path matches are case sensitive
    if ((sig_uri.host() == test_uri.host()) &&
        (sig_uri.scheme() == test_uri.scheme())) {
      // Check the regex pattern for the allowed URL
      const std::regex pat(sig_uri.path());
      if (std::regex_match(test_uri.path(), pat)) {
        return true;
      }
    }
  }
  return false;
}

Status getRuleFromURL(const std::string& url, std::string& rule) {
  auto yaraParser = getYaraParser();
  if (isNull(yaraParser)) {
    return Status::failure("YARA config parser plugin not found");
  }

  try {
    auto signature_set = yaraParser->url_allow_set();
    if (!isRuleUrlAllowed(signature_set, url)) {
      VLOG(1) << "YARA signature url " << url << " not allowed";
      return Status::failure("YARA signature url not allowed");
    }

    http::Client client(TLSTransport().getInternalOptions());
    http::Response response;
    http::Request request(url);

    response = client.get(request);
    // Check for the status code and update the rule string on success
    // and result has been transmitted to the message body
    if (response.status() == 200) {
      rule = response.body();
    } else {
      VLOG(1) << "Can't fetch rules from url response code: "
              << response.status();
    }
  } catch (const std::exception& e) {
    return Status::failure(e.what());
  }

  return Status::success();
}

void doYARAScan(YR_RULES* rules,
                const std::string& path,
                QueryData& results,
                YaraRuleType yr_type,
                const std::string& sigfile) {
  Row row;

  // These are default values, to be updated in YARACallback.
  row["count"] = INTEGER(0);
  row["matches"] = SQL_TEXT("");
  row["strings"] = SQL_TEXT("");
  row["tags"] = SQL_TEXT("");
  row["sig_group"] = SQL_TEXT("");
  row["sigfile"] = SQL_TEXT("");
  row["sigrule"] = SQL_TEXT("");

  // This could use target_path instead to be consistent with yara_events.
  row["path"] = path;

  switch (yr_type) {
  case YC_GROUP:
    row["sig_group"] = SQL_TEXT(sigfile);
    break;
  case YC_FILE:
    row["sigfile"] = SQL_TEXT(sigfile);
    break;
  case YC_RULE:
    row["sigrule"] = SQL_TEXT(sigfile);
    break;
  case YC_URL:
    row["sigurl"] = SQL_TEXT(sigfile);
    break;
  case YC_NONE:
    break;
  }

  // Perform the scan, using the static YARA subscriber callback.
  int result = yr_rules_scan_file(
      rules, path.c_str(), SCAN_FLAGS_FAST_MODE, YARACallback, (void*)&row, 0);
  if (result == ERROR_SUCCESS) {
    results.push_back(std::move(row));
  }
}

Status getYaraRules(YARAConfigParser parser,
                    YaraRuleSet signature_set,
                    YaraRuleType sign_type,
                    YaraScanContext& context) {
  if (isNull(parser)) {
    return Status::failure("YARA config parser plugin is null");
  }

  auto& rules_map = parser->rules();

  // Compile signature string and add them to the scan context
  for (const auto& sign : signature_set) {
    // Check if the signature string has been used/compiled
    const auto signature_hash = hashStr(sign, sign_type);
    if (rules_map.count(signature_hash) > 0) {
      context.insert(std::make_pair(sign_type, sign));
      continue;
    }

    YaraRulesHandle handle(nullptr);

    switch (sign_type) {
    case YC_FILE: {
      auto path = (boost::filesystem::path(sign).is_relative())
                      ? (kYARAHome + sign)
                      : sign;
      auto result = compileSingleFile(path);
      if (result.isError()) {
        LOG(WARNING) << "YARA compile error: "
                     << result.getError().getMessage();
        continue;
      }
      handle = result.take();
      break;
    }

    case YC_RULE: {
      auto result = compileFromString(sign);
      if (result.isError()) {
        LOG(WARNING) << "YARA compile error: "
                     << result.getError().getMessage();
        continue;
      }

      handle = result.take();
      break;
    }

    case YC_URL: {
      std::string rule_string;
      auto request = getRuleFromURL(sign, rule_string);
      // rule_string will be empty if there is partial fetch or
      // the function failed to fetch the YARA rules from URL
      if (!request.ok() || rule_string.empty()) {
        LOG(WARNING) << "Failed to get YARA rule url: " << sign;
        continue;
      }

      auto result = compileFromString(rule_string);
      if (result.isError()) {
        LOG(WARNING) << "YARA compile error: "
                     << result.getError().getMessage();
        continue;
      }

      handle = result.take();
      break;
    }

    default:
      return Status::failure("Unsupported YARA rule type");
    }

    // Cache the compiled rules by setting the unique hashed signature
    // string as the lookup name. Additional signature file uses will
    // skip the compile step and be added to the scan context
    rules_map.insert_or_assign(signature_hash, std::move(handle));
    context.insert(std::make_pair(sign_type, sign));
  }

  return Status::success();
}

QueryData genYara(QueryContext& context) {
  QueryData results;
  YaraScanContext scanContext;

  // Initialize yara library
  auto init_status = yaraInitialize();
  if (!init_status.ok()) {
    LOG(WARNING) << init_status.toString();
    return results;
  }

  auto yaraParser = getYaraParser();
  if (isNull(yaraParser)) {
    return results;
  }

  // The query must specify one of sig_groups, sigfile, or sigrule
  // for scan. The signature rules are compiled and added to the
  // scan context.
  if (context.hasConstraint("sig_group", EQUALS)) {
    auto groups = context.constraints["sig_group"].getAll(EQUALS);
    for (const auto& group : groups) {
      scanContext.insert(std::make_pair(YC_GROUP, group));
    }
  }

  // Compile signature file if query has sigfile constraint and
  // add them to the scan context
  if (context.hasConstraint("sigfile", EQUALS)) {
    auto sigfiles = context.constraints["sigfile"].getAll(EQUALS);
    auto status = getYaraRules(yaraParser, sigfiles, YC_FILE, scanContext);
    if (!status.ok()) {
      LOG(WARNING) << status.toString();
      return results;
    }
  }

  // Compile signature string if query has sigrule constraint and
  // add them to the scan context
  if (context.hasConstraint("sigrule", EQUALS)) {
    auto sigrules = context.constraints["sigrule"].getAll(EQUALS);
    auto status = getYaraRules(yaraParser, sigrules, YC_RULE, scanContext);
    if (!status.ok()) {
      LOG(WARNING) << status.toString();
      return results;
    }
  }

  if (context.hasConstraint("sigurl", EQUALS)) {
    auto sigurls = context.constraints["sigurl"].getAll(EQUALS);
    auto status = getYaraRules(yaraParser, sigurls, YC_URL, scanContext);
    if (!status.ok()) {
      LOG(WARNING) << status.toString();
      return results;
    }
  }

  // scan context is empty. One of sig_group, sigfile, or sigrule
  // must be specified with the query
  if (scanContext.empty()) {
    VLOG(1) << "Query must specify sig_group, sigfile, or sigrule for scan";
    return results;
  }

  // Get all the paths specified
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

  // Scan every path pair with the yara rules
  auto& rules = yaraParser->rules();
  for (const auto& path : paths) {
    for (const auto& sign : scanContext) {
      auto hash = hashStr(sign.second, sign.first);
      auto rules_it = rules.find(hash);
      if (rules_it != rules.end()) {
        doYARAScan(rules_it->second.get(),
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
  // Also cleanup the cache block if rules are downloaded from url
  for (const auto& sign : scanContext) {
    if (sign.first == YC_RULE || sign.first == YC_URL) {
      auto hash = hashStr(sign.second, sign.first);
      auto it = rules.find(hash);
      if (it != rules.end()) {
        rules.erase(hash);
      }
    }
  }

  // Clean-up after finish scanning; If yr_initialize is called
  // more than once it will decrease the reference counter and return
  auto fini_status = yaraFinalize();
  if (!fini_status.ok()) {
    LOG(WARNING) << fini_status.toString();
  }

#ifdef OSQUERY_LINUX
  // Attempt to release some unused memory kept by malloc internal caching
  releaseRetainedMemory();
#endif

  return results;
}
} // namespace tables
} // namespace osquery
