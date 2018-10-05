
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for process_envs
// Spec file: specs/posix/process_envs.table

#include <osquery/tests/integration/tables/helper.h>

#include <algorithm>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

namespace osquery {

class ProcessEnvs : public IntegrationTableTest {
 public:
  ProcessEnvs()
      : env_name("OSQUERY_TEST_ENV_NAME"),
        env_value("osquery_test_env_value") {}

  void SetUp() override {
    ::setenv(env_name.c_str(), env_value.c_str(), 1);
  }

  void TearDown() override {
    ::unsetenv(env_name.c_str());
  }

  const std::string env_name;
  const std::string env_value;
};

TEST_F(ProcessEnvs, test_sanity) {
  QueryData data = execute_query("select * from process_envs");

  ValidatatioMap row_map = {
      {"pid", NonNegativeInt},
      {"key", NonEmptyString},
      {"value", NormalType},
  };
  validate_rows(data, row_map);

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    std::string pid = std::to_string(::getpid());
    Row r{
        {"pid", pid},
        {"key", env_name},
        {"value", env_value},
    };

    ASSERT_NE(std::find(data.begin(), data.end(), r), data.end())
        << "Test env variable not found";
  }
}

} // namespace osquery
