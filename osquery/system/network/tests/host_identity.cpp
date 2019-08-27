/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/system/network/hostname.h>

#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/registry_interface.h>
#include <osquery/system.h>

#include <boost/uuid/string_generator.hpp>

#include <gtest/gtest.h>

namespace osquery {

DECLARE_bool(disable_database);

class HostIdentityTests : public testing::Test {
 public:
  void SetUp() override {
    FLAGS_disable_database = true;
    Initializer::platformSetup();
    registryAndPluginInit();
    DatabasePlugin::initPlugin();
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
