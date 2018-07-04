#include <osquery/killswitch/killswitch_refreshable_plugin.h>
#include <string>

namespace osquery {

class KillswitchFilesystem : public KillswitchRefreshablePlugin {
 public:
  KillswitchFilesystem();
  KillswitchFilesystem(const std::string& conf_path);

 protected:
  virtual Status refresh() override;

 private:
  std::string conf_path_;

  FRIEND_TEST(KillswitchTests, test_killswitch_filesystem_plugin);
};

} // namespace osquery
