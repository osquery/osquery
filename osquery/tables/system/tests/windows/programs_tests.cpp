/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry.h>
#include <osquery/tables/system/windows/programs.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace tables {

class ProgramsTablesTest : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

TEST_F(ProgramsTablesTest, test_decode_msi_registry_guid) {
  // Empty guid
  std::string emptyGUID = "";
  ASSERT_EQ(decodeMsiRegistryGuid(emptyGUID), "");

  // Invalid length
  std::string invalidCompactGUID = "{0D8797326E7E4114DAECB3B66B9CD045}";
  ASSERT_EQ(decodeMsiRegistryGuid(invalidCompactGUID), "");

  // Valid conversion
  std::string validCompactGUID = "0D8797326E7E4114DAECB3B66B9CD045";
  ASSERT_EQ(decodeMsiRegistryGuid(validCompactGUID),
            "{237978D0-E7E6-4114-ADCE-3B6BB6C90D54}");
}

} // namespace tables
} // namespace osquery
