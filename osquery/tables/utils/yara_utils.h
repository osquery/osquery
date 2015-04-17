/*
 *  Copyright (c) 2015, Welsey Shields
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/config.h>
#include <osquery/tables.h>

#ifdef CONCAT
#undef CONTACT
#endif
#include <yara.h>

namespace osquery {
namespace tables {


void YARACompilerCallback(int error_level,
                          const char* file_name,
                          int line_number,
                          const char* message,
                          void* user_data);

Status compileSingleFile(const std::string file, YR_RULES** rule);

Status handleRuleFiles(const std::string& category,
                       const pt::ptree& rule_files,
                       std::map<std::string, YR_RULES *>* rules);

int YARACallback(int message, void *message_data, void *user_data);

/**
 * @brief A simple ConfigParserPlugin for a "yara" dictionary key.
 *
 * A straight forward ConfigParserPlugin that requests a single "yara" key.
 * This stores a rather trivial "yara" data key. The accessor will be
 * redundant since this is so simple:
 *
 * Pseudo-code:
 *   getParser("yara")->getKey("yara");
 */
class YARAConfigParserPlugin : public ConfigParserPlugin {
 public:
  /// Request a single "yara" top level key.
  std::vector<std::string> keys() { return {"yara"}; }

  // Retrieve compiled rules.
  std::map<std::string, YR_RULES *> rules() { return rules_; }

 private:
  // Store compiled rules in a map (group => rules).
  std::map<std::string, YR_RULES *> rules_;

  /// Store the signatures and file_paths and compile the rules.
  Status update(const std::map<std::string, ConfigTree>& config) {
    Status status;
    const auto& yara_config = config.at("yara");
    if (yara_config.count("signatures") > 0) {
      const auto& signatures = yara_config.get_child("signatures");
      data_.add_child("signatures", signatures);
      for (const auto& element : signatures) {
        VLOG(1) << "Compiling YARA signature group: " << element.first;
        status = handleRuleFiles(element.first, element.second, &rules_);
        if (!status.ok()) {
          VLOG(1) << "YARA rule compile error: " << status.getMessage();
          return status;
        }
      }
    }
    if (yara_config.count("file_paths") > 0) {
      const auto& file_paths = yara_config.get_child("file_paths");
      data_.add_child("file_paths", file_paths);
    }
    return Status(0, "OK");
  }
};

}
}
