#include <osquery/core.h>
#include <osquery/database.h>

namespace osquery {
namespace tables {

QueryData genArpCache() {
  QueryData results;

  throw std::domain_error("Table not implemented for FreeBSD");

  return results;
}

QueryData genRoutes() {
  QueryData results;

  throw std::domain_error("Table not implemented for FreeBSD");

  return results;
}
}
}
