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

#include <cerrno>
#include <sys/stat.h>

#include <osquery/config/config.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/remote/uri.h>
#include <osquery/tables/yara/yara_utils.h>
#include <osquery/utils/expected/expected.h>
#include <osquery/utils/status/status.h>

namespace osquery {

DECLARE_bool(enable_yara_string);

namespace {
Status verifyRuleFilePointer(FILE* rule_file, const std::string& file_path) {
  int file_fd = -1;

  auto status = platformFileno(rule_file, file_fd);

  if (!status.ok()) {
    return Status::failure(
        "Could not convert FILE pointer to file descriptor of file " +
        file_path + ", error " + std::to_string(status.getCode()));
  }

  auto opt_is_file = platformIsFile(file_fd);

  if (!opt_is_file.has_value()) {
    return Status::failure("Could not determine if " + file_path +
                           " is a file");
  }

  if (!opt_is_file.value()) {
    return Status::failure("The rules file path doesn't point to a file");
  }

  return Status::success();
}

using YaraCompilerDeleter = void (*)(YR_COMPILER*);
using YaraCompilerHandle = std::unique_ptr<YR_COMPILER, YaraCompilerDeleter>;
using YaraCompilerCreateResult =
    Expected<YaraCompilerHandle, YaraCompilerError>;
YaraCompilerCreateResult createCompiler() {
  YR_COMPILER* compiler = nullptr;

  int result = yr_compiler_create(&compiler);
  if (result != ERROR_SUCCESS) {
    return YaraCompilerCreateResult::failure("Could not create compiler: " +
                                             std::to_string(result));
  }

  return YaraCompilerHandle(compiler, [](YR_COMPILER* compiler) {
    if (compiler) {
      yr_compiler_destroy(compiler);
    }
  });
}

} // namespace

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
Status yaraInitialize(void) {
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
YaraCompilerResult compileSingleFile(const std::string& file) {
  auto compiler_result = createCompiler();

  if (compiler_result.isError()) {
    return compiler_result.takeError();
  }

  auto compiler = compiler_result.take();

  yr_compiler_set_callback(compiler.get(), YARACompilerCallback, nullptr);

  YR_RULES* tmp_rules = nullptr;
  VLOG(1) << "Loading YARA signature file: " << file;

  // First attempt to load the file, in case it is saved (pre-compiled)
  // rules.
  //
  // If you want to use saved rule files you must have them all in a single
  // file. This is easy to accomplish with yarac(1).
  auto result = yr_rules_load(file.c_str(), &tmp_rules);

  if (result == ERROR_SUCCESS) {
    return YaraCompilerResult::success(tmp_rules);
  }

  if (result != ERROR_INVALID_FILE) {
    return YaraCompilerResult::failure("Error loading YARA rules: " +
                                       std::to_string(result));
  }

  // The rule file was not a pre-compiled rules file, try to compile it
  FILE* rule_file = fopen(file.c_str(), "r");

  if (rule_file == nullptr) {
    return YaraCompilerResult::failure("Could not open file: " + file);
  }

  /* Verify that the path opened is actually a file,
     since fopen could be used to open a directory too,
     which would cause a leak in Yara. */
  Status status = verifyRuleFilePointer(rule_file, file);
  if (!status.ok()) {
    fclose(rule_file);
    return YaraCompilerResult::failure(status.getMessage());
  }

  int errors =
      yr_compiler_add_file(compiler.get(), rule_file, nullptr, file.c_str());

  fclose(rule_file);
  rule_file = nullptr;

  if (errors > 0) {
    // Errors printed via callback.
    return YaraCompilerResult::failure("Compilation errors");
  }

  /* All the rules for this category have been compiled,
     get a reference to them */
  result = yr_compiler_get_rules(compiler.get(), &tmp_rules);

  if (result != ERROR_SUCCESS) {
    return YaraCompilerResult::failure("Insufficient memory to get YARA rules");
  }

  return YaraCompilerResult::success(tmp_rules);

} // namespace osquery

/**
 * Compile yara rules from string and load it into rule pointer.
 */
YaraCompilerResult compileFromString(const std::string& rule_defs) {
  auto compiler_result = createCompiler();

  if (compiler_result.isError()) {
    return compiler_result.takeError();
  }

  auto compiler = compiler_result.take();

  yr_compiler_set_callback(compiler.get(), YARACompilerCallback, nullptr);

  auto result =
      yr_compiler_add_string(compiler.get(), rule_defs.c_str(), nullptr);
  if (result > 0) {
    return YaraCompilerResult::failure("Compilation error " +
                                       std::to_string(result));
  }

  YR_RULES* tmp_rules = nullptr;

  result = yr_compiler_get_rules(compiler.get(), &tmp_rules);
  if (result != ERROR_SUCCESS) {
    return YaraCompilerResult::failure("Insufficient memory to get YARA rules");
  }

  // The yara rule strings are set to private unless it is disabled. This
  // will protect from data exfiltration
  if (!FLAGS_enable_yara_string) {
    YR_RULE* rule = nullptr;
    yr_rules_foreach(tmp_rules, rule) {
      if (rule->strings) {
        rule->strings->flags = rule->strings->flags | STRING_FLAGS_PRIVATE;
      }
    }
  }

  return YaraCompilerResult::success(tmp_rules);
}

/**
 * Given a vector of strings, attempt to compile them and store the result
 * in the map under the given category.
 */
Status handleRuleFiles(const std::string& category,
                       const rapidjson::Value& rule_files,
                       std::map<std::string, YaraRulesHandle>& rules) {
  auto compiler_result = createCompiler();

  if (compiler_result.isError()) {
    return Status::failure(compiler_result.getError().getMessage());
  }

  auto compiler = compiler_result.take();

  yr_compiler_set_callback(compiler.get(), YARACompilerCallback, nullptr);

  bool compiled = false;
  for (const auto& item : rule_files.GetArray()) {
    if (!item.IsString()) {
      continue;
    }

    YR_RULES* tmp_rules = nullptr;
    std::string rule = item.GetString();
    if (boost::filesystem::path(rule).is_relative()) {
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
    auto result = yr_rules_load(rule.c_str(), &tmp_rules);
    if (result != ERROR_SUCCESS && result != ERROR_INVALID_FILE) {
      return Status(1, "YARA load error " + std::to_string(result));
    } else if (result == ERROR_SUCCESS) {
      rules.insert_or_assign(category, tmp_rules);
    } else {
      compiled = true;
      // Try to compile the rules.
      FILE* rule_file = fopen(rule.c_str(), "r");

      if (rule_file == nullptr) {
        return Status(1, "Could not open file: " + rule);
      }

      /* Verify that the path opened is actually a file,
       since fopen could be used to open a directory too,
       which would cause a leak in Yara. */
      Status status = verifyRuleFilePointer(rule_file, rule);
      if (!status.ok()) {
        fclose(rule_file);
        return status;
      }

      int errors = yr_compiler_add_file(
          compiler.get(), rule_file, nullptr, rule.c_str());

      fclose(rule_file);
      rule_file = nullptr;

      if (errors > 0) {
        // Errors printed via callback.
        return Status(1, "Compilation errors");
      }
    }
  }

  if (compiled) {
    YR_RULES* new_rules = nullptr;
    auto result = yr_compiler_get_rules(compiler.get(), &new_rules);

    if (result != ERROR_SUCCESS) {
      return Status(1, "Insufficient memory to get YARA rules");
    }

    // All the rules for this category have been compiled, save them in the map.
    rules.insert_or_assign(category, new_rules);
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
