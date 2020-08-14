/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
