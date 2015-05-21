#include <osquery/config.h>
#include <osquery/tables.h>

namespace osquery {

/**
 * @brief A simple ConfigParserPlugin for a "packs" dictionary key.
 *
 */
class QueryPackConfigParserPlugin : public ConfigParserPlugin {
 public:
  /// Request "packs" top level key.
  std::vector<std::string> keys() { return {"packs"}; }

  std::map<std::string, pt::ptree> QueryPackParsePacks(const pt::ptree& raw_packs, bool check_platform, bool check_version);

 private:
  /// Store the signatures and file_paths and compile the rules.
  Status update(const std::map<std::string, ConfigTree>& config);
};

}
