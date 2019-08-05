#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {
class UserassistTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(UserassistTest, test_sanity) {
  QueryData const rows = execute_query("select * from userassist");
  ASSERT_GT(rows.size(), 0ul);
  ValidatatioMap row_map = {
      {"path", NonEmptyString},
      {"last_execution_time", NormalType},
      {"count", NormalType},
      {"sid", NonEmptyString},
  };
  validate_rows(rows, row_map);
}
} // namespace table_tests
} // namespace osquery
