
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for ec2_instance_metadata
// Spec file: specs/linux/ec2_instance_metadata.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class ec2InstanceMetadata : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(ec2InstanceMetadata, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from ec2_instance_metadata");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"instance_id", NormalType}
  //      {"instance_type", NormalType}
  //      {"architecture", NormalType}
  //      {"region", NormalType}
  //      {"availability_zone", NormalType}
  //      {"local_hostname", NormalType}
  //      {"local_ipv4", NormalType}
  //      {"mac", NormalType}
  //      {"security_groups", NormalType}
  //      {"iam_arn", NormalType}
  //      {"ami_id", NormalType}
  //      {"reservation_id", NormalType}
  //      {"account_id", NormalType}
  //      {"ssh_public_key", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
