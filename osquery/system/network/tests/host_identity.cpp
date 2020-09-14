/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/system/network/hostname.h>

#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry_interface.h>

#include <boost/uuid/string_generator.hpp>

#include <gtest/gtest.h>

namespace osquery {

class HostIdentityTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

TEST_F(HostIdentityTests, create_localhost) {
  auto const v1 = HostIdentity::localhost();
  auto const v2 = HostIdentity::localhost();

  EXPECT_FALSE(v1.fqdn.empty());

  // will throw an exception if uuid is invalid
  boost::uuids::string_generator()(v1.uuid);

  EXPECT_EQ(v1.fqdn, v2.fqdn);
  EXPECT_EQ(v1.uuid, v2.uuid);
}

} // namespace osquery
