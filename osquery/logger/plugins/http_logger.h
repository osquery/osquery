#include <vector>
#include <string>
#include <osquery/registry.h>
#include <osquery/logger.h>
#include <osquery/filesystem.h>

namespace osquery {
class HTTPLoggerPlugin : public LoggerPlugin {
 private:
  unsigned log_num;

 public:
  Status setUp();
  Status logString(const std::string& s);
  Status init(const std::string& name, const std::vector<StatusLogLine>& log);
  Status logStatus(const std::vector<StatusLogLine>& log);
};
}