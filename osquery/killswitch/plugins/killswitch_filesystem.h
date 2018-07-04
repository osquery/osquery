#include <map>
#include <string>

namespace osquery {

class KillswitchFilesystem : public KillswitchPlugin {
 protected:
  virtual Status refresh() override;

};

} // namespace osquery
