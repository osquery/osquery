#include <iostream>
#include <string>

#include <osquery/killswitch.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

namespace osquery{




  class KillswitchTest : public KillswitchPlugin{
    bool isEnabled(std::string switchKey){
      std::cerr<<"hello"<<std::endl;
      return true;
    }
    Status call(const PluginRequest& request,
                        PluginResponse& response){

                        }
                        Status setUp() {

                        }
  };
  REGISTER(KillswitchTest,
           "killswitch",
           "killswitch_test");

}
