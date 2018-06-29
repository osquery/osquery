#include <iostream>
#include <string>

#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

namespace osquery {

class KillswitchTest : public KillswitchPlugin {
  Status isEnabled(const std::string& key, bool& isEnabled) override{
    std::cerr << "hello" << std::endl;
    isEnabled = true;
    return Status();
  }
  Status refresh() override{
    std::cerr << " refreshed " << std::endl;
  }
};
REGISTER(KillswitchTest, "killswitch", "killswitch_test");

} // namespace osquery
