#include "osquery/remote/serializers/json.h"
#include <osquery/killswitch/killswitch_refreshable_plugin.h>
#include <string>
#include <osquery/expected.h>

namespace osquery {

class KillswitchJSON : public KillswitchRefreshablePlugin {
 public:
   enum class GetJSONError{

   }
 protected:
  ExpectedSuccess<KillswitchRefreshablePlugin::RefreshError> refresh() override;
  virtual ExpectedSuccess<GetJSONError> getJSON(std::string& content) = 0;
};

} // namespace osquery
