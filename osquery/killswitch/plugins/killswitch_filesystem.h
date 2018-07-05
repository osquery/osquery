
#include "osquery/killswitch/plugins/killswitch_json.h"
#include <string>

namespace osquery {

class KillswitchFilesystem : public KillswitchJSON {
 public:
  KillswitchFilesystem();
  KillswitchFilesystem(const boost::filesystem::path& conf_path);

 protected:
  Status getJSON(std::string& content) override;

 private:
  const boost::filesystem::path conf_path_;

  FRIEND_TEST(KillswitchFilesystemTests, test_killswitch_filesystem_plugin);
};

} // namespace osquery
