
#include "osquery/killswitch/killswitch_refreshable_plugin.h"
#include <string>

namespace osquery {

class KillswitchFilesystem : public KillswitchRefreshablePlugin {
 public:
  KillswitchFilesystem();
  KillswitchFilesystem(const boost::filesystem::path& conf_path);

 protected:
  ExpectedSuccess<KillswitchRefreshablePlugin::RefreshError> refresh() override;

 private:
  const boost::filesystem::path conf_path_;

  FRIEND_TEST(KillswitchFilesystemTests, test_killswitch_filesystem_plugin);
};

} // namespace osquery
