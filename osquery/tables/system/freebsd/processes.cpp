#include "osquery/core.h"
#include "osquery/database.h"

namespace osquery {
namespace tables {

QueryData genProcessEnvs() {
  QueryData results;

  throw std::domain_error("Table not implemented for FreeBSD");

  return results;
}

QueryData genProcesses() {
  QueryData results;

  throw std::domain_error("Table not implemented for FreeBSD");

  return results;
}

QueryData genProcessOpenFiles() {
  QueryData results;

  throw std::domain_error("Table not implemented for FreeBSD");

  return results;
}
}
}
