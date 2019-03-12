/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/registry.h>

#include <gtest/gtest.h>

#include <boost/io/detail/quoted_manip.hpp>

#include <unordered_set>
#include <vector>

namespace osquery {
namespace {

class PluginSdkRegistryTests : public testing::Test {};

TEST_F(PluginSdkRegistryTests, there_is_no_registered_plugin_in_sdk) {
  for (auto const& ptr : AutoRegisterInterface::plugins()) {
    EXPECT_TRUE(ptr->optional_)
        << " unexpected non internal plugin in sdk:"
        << " (type: " << boost::io::quoted(ptr->type_)
        << ", name: " << boost::io::quoted(ptr->name_) << ")";
  }
}

auto const mandatory_registries_ = std::vector<std::string>{
    "config",
    "config_parser",
    "database",
    "distributed",
    "enroll",
    "event_publisher",
    "event_subscriber",
    "killswitch",
    "logger",
    "numeric_monitoring",
    "sql",
    "table",

    // experimental
    "osquery_events_stream",
};

TEST_F(PluginSdkRegistryTests, whether_all_mandatory_registries_are_in_sdk) {
  auto known_registries = std::unordered_set<std::string>{};
  for (auto const& ptr : AutoRegisterInterface::registries()) {
    EXPECT_FALSE(known_registries.count(ptr->name_))
        << " duplicated registry " << boost::io::quoted(ptr->name_);
    known_registries.emplace(ptr->name_);
  }
  for (auto const& name : mandatory_registries_) {
    EXPECT_TRUE(known_registries.count(name))
        << " missing mandatory registry " << boost::io::quoted(name);
  }
}

} // namespace
} // namespace osquery
