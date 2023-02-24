/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for cpu_info
// Spec file: specs/cpu_info.table

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {

class cpuInfo : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(cpuInfo, test_sanity) {
  const QueryData data = execute_query("select * from cpu_info");
  ASSERT_GE(data.size(), 1ul);
  ValidationMap row_map = {{"device_id", NonEmptyString},
                           {"model", NormalType},
                           {"manufacturer", NormalType},
                           {"processor_type", NonNegativeOrErrorInt},
                           {"number_of_cores", NonNegativeOrErrorInt},
                           {"logical_processors", NonNegativeOrErrorInt},
                           {"address_width", NonNegativeOrErrorInt},
                           {"max_clock_speed", NonNegativeOrErrorInt}};

#if defined(OSQUERY_DARWIN) && defined(__aarch64__)
  row_map.emplace("number_of_efficiency_cores", NonNegativeInt);
  row_map.emplace("number_of_performance_cores", NonNegativeInt);
  row_map.emplace("socket_designation", EmptyOk);
  row_map.emplace("current_clock_speed", EmptyOk);
  row_map.emplace("cpu_status", EmptyOk);
#else
#ifdef OSQUERY_DARWIN
  row_map.emplace("number_of_efficiency_cores", EmptyOk);
  row_map.emplace("number_of_performance_cores", EmptyOk);
#endif
  row_map.emplace("socket_designation", NonEmptyString);
  row_map.emplace("current_clock_speed", NonNegativeOrErrorInt);
  row_map.emplace("cpu_status", NonNegativeOrErrorInt);
#endif

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    row_map.emplace("availability", NonNegativeOrErrorInt);
  }

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
