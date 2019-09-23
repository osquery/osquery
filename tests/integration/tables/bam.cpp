#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
	namespace table_tests {
		class BamTest : public testing::Test {
         protected:
			 voaid SetUp() override {
            SetUpEnvironment();
				  }
        };

		TEST_F(BamTest, test_sanity) {
          QueryData const rows = execute_query("select * from bam;");
		  QueryData const specific_query_rows = execute_query(
                      "select * from bam where path is 'SequenceNumber'; ");
          ASSERT_GT(rows.size(), 0ul);
          ASSERT_GT(rows.size(), 1ul);

		  ValidationMap row_map = {{"path", NonEmptyString},
                                   {"last_execution_time", NormalType},
                                   {"sid", NonEmptyString}};
          validate_rows(rows, row_map);
          validate_rows(specific_query_rows, row_map);


        }
        }
}