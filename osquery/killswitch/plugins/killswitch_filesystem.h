#include "osquery/killswitch/plugins/killswitch_json.h"
#include <string>

namespace osquery {

class KillswitchFilesystem : public KillswitchJSON {
 public:
  KillswitchFilesystem();
  KillswitchFilesystem(const std::string& conf_path);

 protected:
  virtual Status getJSON(std::string& content) override;

 private:
  std::string conf_path_;

  FRIEND_TEST(KillswitchFilesystemTests, test_killswitch_filesystem_plugin);
};

} // namespace osquery
