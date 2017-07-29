#include "osquery/events/linux/tests/audit_tests_common.h"
#include <ctime>
#include <sstream>

namespace osquery {
std::string generateAuditId(std::uint32_t event_id) noexcept {
  std::stringstream str_helper;
  str_helper << std::time(nullptr) << ".000:" << event_id;

  return str_helper.str();
}
}
