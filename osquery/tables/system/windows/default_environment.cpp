#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {
static std::string kEnvironmentKey =
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session "
    "Manager\\Environment";

QueryData genDefaultEnvironment(QueryContext& context) {
  QueryData results;
  auto environment =
      SQL::selectAllFrom("registry", "key", EQUALS, kEnvironmentKey);

  for (const auto& env : environment) {
    Row r;
    r["variable"] = std::move(env.at("name"));
    r["value"] = std::move(env.at("data"));
    r["expand"] = INTEGER(env.at("type") == "REG_EXPAND_SZ");
    results.push_back(std::move(r));
  }

  return results;
}
} // namespace tables
} // namespace osquery
