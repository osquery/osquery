#include "osquery/remote/serializers/json.h"
#include <osquery/expected.h>
#include <osquery/killswitch/killswitch_refreshable_plugin.h>
#include <string>

namespace osquery {

class KillswitchJSON : public KillswitchRefreshablePlugin {
 protected:
  ExpectedSuccess<KillswitchRefreshablePlugin::RefreshError> refresh() override;
  enum class GetJSONError { MissingConfigFile = 1, NetworkFailure = 2 };
  virtual Expected<std::string, GetJSONError> getJSON() = 0;

  friend class KillswitchJSONTestHelper;
};

} // namespace osquery
