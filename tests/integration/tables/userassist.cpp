#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {
class UserassistTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

std::string rot_decode(std::string& value_key_reg) {
  std::string decoded_value_key;

  for (std::size_t i = 0; i < value_key_reg.size(); i++) {
    if (isalpha(value_key_reg[i])) {
      if (value_key_reg[i] >= 'a' && value_key_reg[i] <= 'm') {
        decoded_value_key.append(1, value_key_reg[i] + 13);
      } else if (value_key_reg[i] >= 'm' && value_key_reg[i] <= 'z') {
        decoded_value_key.append(1, value_key_reg[i] - 13);
      } else if (value_key_reg[i] >= 'A' && value_key_reg[i] <= 'M') {
        decoded_value_key.append(1, value_key_reg[i] + 13);
      } else if (value_key_reg[i] >= 'M' && value_key_reg[i] <= 'Z') {
        decoded_value_key.append(1, value_key_reg[i] - 13);
      }
    } else {
      decoded_value_key.append(1, value_key_reg[i]);
    }
  }
  return decoded_value_key;
}

TEST(Rot13Test, DecodeData) {

  std::string encoded_data = "Gur dhvpx oebja sbk whzcf bire gur ynml qbt";
  std::string decoded_data = rot_decode(encoded_data);
  ASSERT_TRUE(decoded_data == "The quick brown fox jumps over the lazy dog");
}

TEST_F(userassistTest, test_sanity) {
  QueryData const rows = execute_query("select * from userassist");
  QueryData const specific_query_rows = execute_query(
      "select * from userassist where path is 'Microsoft.Windows.Explorer'");
  ASSERT_GT(rows.size(), 0ul);
  ASSERT_EQ(specific_query_rows.size(), 1ul);
  ValidatatioMap row_map = {
      {"path", NonEmptyString},
      {"last_execution_time", NormalType},
      {"count", NormalType},
      {"sid", NonEmptyString},
  };
  validate_rows(rows, row_map);
  validate_rows(specific_query_rows, row_map);
}
} // namespace table_tests
} // namespace osquery
