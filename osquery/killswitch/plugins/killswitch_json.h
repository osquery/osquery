#include "osquery/remote/serializers/json.h"
#include <osquery/killswitch/killswitch_refreshable_plugin.h>
#include <string>

namespace osquery {

class KillswitchJSON : public KillswitchRefreshablePlugin {
 public:
 protected:
  virtual Status refresh() override;
  virtual Status getJSON(std::string& content) = 0;
};

} // namespace osquery
