/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/system/darwin/packages.h>

namespace osquery {
namespace tables {

class PackagesTests : public testing::Test {};

TEST_F(PackagesTests, test_bom_parsing) {
  std::string content;
  auto test_bom_path = (getTestConfigDirectory() / "test_bom.bom").string();
  if (!readFile(test_bom_path, content).ok()) {
    return;
  }

  // Create a BOM representation.
  BOM bom(content.c_str(), content.size());
  ASSERT_TRUE(bom.isValid());

  size_t offset = 0;
  auto var = bom.getVariable(&offset);
  ASSERT_FALSE(nullptr == var);
}
} // namespace tables
} // namespace osquery
