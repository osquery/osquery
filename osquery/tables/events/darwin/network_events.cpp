#include <ctime>
#include <osquery/tables.h>
#include <osquery/flags.h>
#include <osquery/system.h>

namespace osquery {
namespace tables {

QueryData genTable(QueryContext &context) {
  Row r;

  r["message"] = "Input from table generator!";

  QueryData results;
  results.push_back(r);
  return results;
}
}
}