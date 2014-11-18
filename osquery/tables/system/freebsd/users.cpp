#include "osquery/core.h"
#include "osquery/database.h"

namespace osquery {

namespace tables {

QueryData genUsers() {
  QueryData results;

  throw std::domain_error("Table not implemented for FreeBSD");

  return results;
}
}
}
