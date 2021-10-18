/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for process_envs
// Spec file: specs/posix/process_envs.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/utils/info/platform_type.h>

#include <boost/io/quoted.hpp>

#include <algorithm>
#include <cstdlib>
#include <sys/types.h>
#include <unistd.h>

namespace osquery {
namespace table_tests {

class ProcessEnvs : public testing::Test {
 public:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(ProcessEnvs, test_sanity) {
  QueryData data = execute_query("select * from process_envs");

  ValidationMap row_map = {
      {"pid", NonNegativeInt},
      {"key", NonEmptyString},
      {"value", NormalType},
  };
  validate_rows(data, row_map);

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    std::string const pid = std::to_string(::getpid());

    for (const auto& var_key : {"USER", "HOME", "LANG", "PATH"}) {
      char const* var_value = std::getenv(var_key);
      if (var_value != nullptr) {
        Row r{
            {"pid", pid},
            {"key", var_key},
            {"value", var_value},
        };

        ASSERT_NE(std::find(data.begin(), data.end(), r), data.end())
            << "Env variable " << boost::io::quoted(var_key)
            << " with value " << boost::io::quoted(var_value) << " not found";
      }
    }
  }
}

} // namespace table_tests
} // namespace osquery
