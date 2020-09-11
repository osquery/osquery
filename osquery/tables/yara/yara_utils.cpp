/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <map>
#include <string>

#include <osquery/config/config.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/yara/yara_utils.h>

#include <osquery/remote/uri.h>

namespace osquery {

DECLARE_bool(enable_yara_string);

bool yaraShouldSkipFile(const std::string& path, mode_t st_mode) {
  // avoid special files /dev/x , /proc/x, FIFO's named-pipes, etc.
  if ((st_mode & S_IFMT) != S_IFREG) {
    return true;
  }

  return false;
}

/**
 * The callback used when there are compilation problems in the rules.
 */
void YARACompilerCallback(int error_level,
                          const char* file_name,
                          int line_number,
                          const YR_RULE* rule,
                          const char* message,
                          void* user_data) {
  std::stringstream ss;
  // file_name will be nullptr on compiling YARA rules from
  // string. It checks the file_name and generate the logs.
  if (file_name == nullptr)
    ss << "YARA rule string ";
  else
    ss << "YARA rule file " << file_name;
  if (error_level == YARA_ERROR_LEVEL_ERROR) {
    VLOG(1) << ss.str() << "(" << line_number << "): error: " << message;
  } else {
    VLOG(1) << ss.str() << "(" << line_number << "): warning: " << message;
  }
}

// yr_initialize maintains a reference count and avoid
// re-initialization
Status yaraInitilize(void) {
  auto result = yr_initialize();
  if (result != ERROR_SUCCESS) {
    return Status::failure("Failed to initialize YARA " +
                           std::to_string(result));
  }
  return Status::success();
}

Status yaraFinalize(void) {
  auto result = yr_finalize();
  if (result != ERROR_SUCCESS) {
    return Status::failure("Failed to finalize YARA " + std::to_string(result));
  }
  return Status::success();
}

/**
 * Compile a single rule file and load it into rule pointer.
 */
Status compileSingleFile(const std::string& file, YR_RULES** rules) {
  YR_COMPILER* compiler = nullptr;

  int result = yr_compiler_create(&compiler);
  if (result != ERROR_SUCCESS) {
    return Status::failure("Could not create compiler: " +
                           std::to_string(result));
  }

  yr_compiler_set_callback(compiler, YARACompilerCallback, nullptr);

  bool compiled = false;
  YR_RULES* tmp_rules;
  VLOG(1) << "Loading YARA signature file: " << file;

  // First attempt to load the file, in case it is saved (pre-compiled)
  // rules.
  //
  // If you want to use saved rule files you must have them all in a single
  // file. This is easy to accomplish with yarac(1).
  result = yr_rules_load(file.c_str(), &tmp_rules);
  if (result != ERROR_SUCCESS && result != ERROR_INVALID_FILE) {
    yr_compiler_destroy(compiler);
    return Status::failure("Error loading YARA rules: " +
                           std::to_string(result));
  } else if (result == ERROR_SUCCESS) {
    *rules = tmp_rules;
  } else {
    compiled = true;
    // Try to compile the rules.
    FILE* rule_file = fopen(file.c_str(), "r");

    if (rule_file == nullptr) {
      yr_compiler_destroy(compiler);
      return Status(1, "Could not open file: " + file);
    }

    int errors =
        yr_compiler_add_file(compiler, rule_file, nullptr, file.c_str());

    fclose(rule_file);
    rule_file = nullptr;

    if (errors > 0) {
      yr_compiler_destroy(compiler);
      // Errors printed via callback.
      return Status::failure("Compilation errors");
    }
  }

  if (compiled) {
    // All the rules for this category have been compiled, save them in the map.
    result = yr_compiler_get_rules(compiler, *(&rules));

    if (result != ERROR_SUCCESS) {
      yr_compiler_destroy(compiler);
      return Status::failure("Insufficient memory to get YARA rules");
    }
  }

  if (compiler != nullptr) {
    yr_compiler_destroy(compiler);
    compiler = nullptr;
  }

  return Status::success();
}

/**
 * Compile yara rules from string and load it into rule pointer.
 */
Status compileFromString(const std::string& rule_defs, YR_RULES** rules) {
  YR_COMPILER* compiler = nullptr;

  auto result = yr_compiler_create(&compiler);
  if (result != ERROR_SUCCESS) {
    return Status::failure("Could not create compiler: " +
                           std::to_string(result));
  }

  yr_compiler_set_callback(compiler, YARACompilerCallback, nullptr);

  result = yr_compiler_add_string(compiler, rule_defs.c_str(), nullptr);
  if (result > 0) {
    yr_compiler_destroy(compiler);
    return Status::failure("Compilation error " + std::to_string(result));
  }

  result = yr_compiler_get_rules(compiler, *(&rules));
  if (result != ERROR_SUCCESS) {
    yr_compiler_destroy(compiler);
    return Status::failure("Insufficient memory to get YARA rules");
  }

  // The yara rule strings are set to private unless it is disabled. This
  // will protect from data exfiltration
  if (!FLAGS_enable_yara_string) {
    YR_RULE* rule = nullptr;
    yr_rules_foreach((*rules), rule) {
      if (rule->strings) {
        rule->strings->flags = rule->strings->flags | STRING_FLAGS_PRIVATE;
      }
    }
  }

  if (compiler != nullptr) {
    yr_compiler_destroy(compiler);
    compiler = nullptr;
  }

  return Status::success();
}

/**
 * Given a vector of strings, attempt to compile them and store the result
 * in the map under the given category.
 */
Status handleRuleFiles(const std::string& category,
                       const rapidjson::Value& rule_files,
                       std::map<std::string, YR_RULES*>& rules) {
  YR_COMPILER* compiler = nullptr;
  int result = yr_compiler_create(&compiler);
  if (result != ERROR_SUCCESS) {
    VLOG(1) << "Could not create compiler: error " + std::to_string(result);
    return Status(1, "YARA compile error " + std::to_string(result));
  }

  yr_compiler_set_callback(compiler, YARACompilerCallback, nullptr);

  bool compiled = false;
  for (const auto& item : rule_files.GetArray()) {
    if (!item.IsString()) {
      continue;
    }

    YR_RULES* tmp_rules = nullptr;
    std::string rule = item.GetString();
    if (rule[0] != '/') {
      rule = kYARAHome + rule;
    }

    // First attempt to load the file, in case it is saved (pre-compiled)
    // rules. Sadly there is no way to load multiple compiled rules in
    // succession. This means that:
    //
    // saved1, saved2
    // results in saved2 being the only file used.
    //
    // Also, mixing source and saved rules results in the saved rules being
    // overridden by the combination of the source rules once compiled, e.g.:
    //
    // file1, saved1
    // result in file1 being the only file used.
    //
    // If you want to use saved rule files you must have them all in a single
    // file. This is easy to accomplish with yarac(1).
    result = yr_rules_load(rule.c_str(), &tmp_rules);
    if (result != ERROR_SUCCESS && result != ERROR_INVALID_FILE) {
      yr_compiler_destroy(compiler);
      return Status(1, "YARA load error " + std::to_string(result));
    } else if (result == ERROR_SUCCESS) {
      // If there are already rules there, destroy them and put new ones in.
      if (rules.count(category) > 0) {
        yr_rules_destroy(rules[category]);
      }

      rules[category] = tmp_rules;
    } else {
      compiled = true;
      // Try to compile the rules.
      FILE* rule_file = fopen(rule.c_str(), "r");

      if (rule_file == nullptr) {
        yr_compiler_destroy(compiler);
        return Status(1, "Could not open file: " + rule);
      }

      int errors =
          yr_compiler_add_file(compiler, rule_file, nullptr, rule.c_str());

      fclose(rule_file);
      rule_file = nullptr;

      if (errors > 0) {
        yr_compiler_destroy(compiler);
        // Errors printed via callback.
        return Status(1, "Compilation errors");
      }
    }
  }

  if (compiled) {
    // All the rules for this category have been compiled, save them in the map.
    result = yr_compiler_get_rules(compiler, &rules[category]);

    if (result != ERROR_SUCCESS) {
      yr_compiler_destroy(compiler);
      return Status(1, "Insufficient memory to get YARA rules");
    }
  }

  if (compiler != nullptr) {
    yr_compiler_destroy(compiler);
    compiler = nullptr;
  }

  return Status::success();
}

/**
 * This is the YARA callback. Used to store matching rules in the row which is
 * passed in as user_data.
 */
int YARACallback(YR_SCAN_CONTEXT* context,
                 int message,
                 void* message_data,
                 void* user_data) {
  if (message == CALLBACK_MSG_RULE_MATCHING) {
    Row* r = (Row*)user_data;
    YR_RULE* rule = (YR_RULE*)message_data;

    if ((*r)["matches"].length() > 0) {
      (*r)["matches"] += "," + std::string(rule->identifier);
    } else {
      (*r)["matches"] = std::string(rule->identifier);
    }

    YR_STRING* string = nullptr;
    yr_rule_strings_foreach(rule, string) {
      YR_MATCH* match = nullptr;
      yr_string_matches_foreach(context, string, match) {
        if ((*r)["strings"].length() > 0) {
          (*r)["strings"] += "," + std::string(string->identifier);
        } else {
          (*r)["strings"] = std::string(string->identifier);
        }

        std::stringstream ss;
        ss << std::hex << (match->base + match->offset);
        (*r)["strings"] += ":" + ss.str();
      }
    }

    const char* tag = nullptr;
    yr_rule_tags_foreach(rule, tag) {
      if ((*r)["tags"].length() > 0) {
        (*r)["tags"] += "," + std::string(tag);
      } else {
        (*r)["tags"] = std::string(tag);
      }
    }

    (*r)["count"] = INTEGER(std::stoi((*r)["count"]) + 1);
  }

  return CALLBACK_CONTINUE;
}

Status YARAConfigParserPlugin::setUp() {
  auto obj = data_.getObject();
  data_.add("yara", obj);

  int result = yr_initialize();
  if (result != ERROR_SUCCESS) {
    LOG(WARNING) << "Unable to initialize YARA (" << result << ")";
    return Status(1, "Unable to initialize YARA");
  }

  return Status::success();
}

Status YARAConfigParserPlugin::update(const std::string& source,
                                      const ParserConfig& config) {
  // The YARA config parser requested the "yara" top-level key in the config.
  if (config.count("yara") == 0) {
    return Status::success();
  }
  const auto& yara_config = config.at("yara").doc();

  // Look for a "signatures" key with the group/file content.
  if (!yara_config.IsObject()) {
    return Status(1);
  }

  if (yara_config.HasMember("signatures")) {
    auto& signatures = yara_config["signatures"];
    if (!signatures.IsObject()) {
      VLOG(1) << "YARA signatures must contain a dictionary";
    } else {
      auto obj = data_.getObject();
      data_.copyFrom(signatures, obj);
      data_.add("signatures", obj);

      for (const auto& element : data_.doc()["signatures"].GetObject()) {
        std::string category = element.name.GetString();
        if (!element.value.IsArray()) {
          VLOG(1) << "YARA signature group " << category << " must be an array";
        } else {
          VLOG(1) << "Compiling YARA signature group: " << category;
          auto status = handleRuleFiles(category, element.value, rules_);
          if (!status.ok()) {
            VLOG(1) << "YARA rule compile error: " << status.getMessage();
            return status;
          }
        }
      }
    }
  }

  if (yara_config.HasMember("signature_urls")) {
    auto& sigurl = yara_config["signature_urls"];
    if (!sigurl.IsArray()) {
      VLOG(1) << "YARA signature_url must be an array";
    } else {
      VLOG(1) << "Compiling YARA signature_url for allowed list";
      for (const auto& element : sigurl.GetArray()) {
        if (element.IsString()) {
          auto url_string = element.GetString();
          try {
            Uri test_uri(url_string);
            url_allow_set_.insert(url_string);
          } catch (const std::exception&) {
            VLOG(1) << "Invalid signature url: " << element.GetString();
          }
        }
      }
    }
  }

  // The "file_paths" set maps the rule groups to the "file_paths" top level
  // configuration key. That similar key keeps the groups of file paths.
  if (yara_config.HasMember("file_paths")) {
    auto& file_paths = yara_config["file_paths"];
    if (file_paths.IsObject()) {
      auto obj = data_.getObject();
      data_.copyFrom(file_paths, obj);
      data_.add("file_paths", obj);
    } else {
      VLOG(1) << "YARA file_paths key is invalid";
    }
  }
  return Status::success();
}

/// Call the simple YARA ConfigParserPlugin "yara".
REGISTER(YARAConfigParserPlugin, "config_parser", "yara");
} // namespace osquery
