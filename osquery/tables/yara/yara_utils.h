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
#undef CONCAT
#endif
#include <yara.h>

namespace pt = boost::property_tree;

namespace osquery {

const std::string kYARAHome{OSQUERY_HOME "/yara/"};

void YARACompilerCallback(int error_level,
                          const char* file_name,
                          int line_number,
                          const char* message,
                          void* user_data);

Status compileSingleFile(const std::string& file, YR_RULES** rule);

Status handleRuleFiles(const std::string& category,
                       const pt::ptree& rule_files,
                       std::map<std::string, YR_RULES*>& rules);

int YARACallback(int message, void* message_data, void* user_data);

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
  std::vector<std::string> keys() const override {
    return {"yara"};
  }

  // Retrieve compiled rules.
  std::map<std::string, YR_RULES*>& rules() {
    return rules_;
  }

  Status setUp() override;

 private:
  // Store compiled rules in a map (group => rules).
  std::map<std::string, YR_RULES*> rules_;

  /// Store the signatures and file_paths and compile the rules.
  Status update(const std::string& source, const ParserConfig& config) override;
};
}
