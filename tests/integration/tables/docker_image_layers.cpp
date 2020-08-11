/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for docker_image_layers
// Spec file: specs/posix/docker_image_layers.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class dockerImageLayersTest : public testing::Test {
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(dockerImageLayersTest, test_sanity) {
  QueryData data = execute_query("select * from docker_images");
  if (data.size() <= 0) { // docker not installed, or issues talking to dockerd,
                          // or no images present
    return;
  }

  data = execute_query("select * from docker_image_layers");
  ASSERT_GT(data.size(), 0ul);
  ValidationMap row_map = {
      {"id", NonEmptyString},
      {"layer_id", NonEmptyString},
      {"layer_order", NonNegativeInt},
  };
  validate_rows(data, row_map);
}
} // namespace table_tests
} // namespace osquery
