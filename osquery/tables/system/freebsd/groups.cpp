#include "osquery/core.h"
#include "osquery/database.h"

namespace osquery {
namespace tables {

std::mutex grpEnumerationMutex;

QueryData genGroups() {
  QueryData results;

  throw std::domain_error("Table not implemented for FreeBSD");

  return results;
}
}
}
