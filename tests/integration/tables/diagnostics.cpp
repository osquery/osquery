#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {
class DiagnosticsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(DiagnosticsTest, test_sanity) {
  QueryData const rows = execute_query("select * from diagnostics");

  QueryData const specific_query_rows = execute_query(
      "select * from diagnostics where process_name is 'Finder' or "
      "process_name is 'Spotlight'");
  ASSERT_GT(rows.size(), 0ul);
  ASSERT_GE(rows.size(), 2ul);

  auto const row_map = ValidatatioMap{
      {"path", NormalType},
      {"diagnostic_start", NormalType},
      {"diagnostic_end", NormalType},
      {"name", NormalType},
      {"uuid", NormalType},
      {"process_name", NormalType},
      {"app_description", NormalType},
      {"foreground", NormalType},
      {"uptime", NormalType},
      {"power_time", NormalType},
      {"active_time", NormalType},
      {"activations", NormalType},
      {"launches", NormalType},
      {"activity_periods", NormalType},
      {"idle_timeouts", NormalType},
      {"count", NormalType},
      {"version", NormalType},
  };
  validate_rows(rows, row_map);
  validate_rows(specific_query_rows, row_map);
}
} // namespace table_tests
} // namespace osquery
