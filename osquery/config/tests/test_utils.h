/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/utils/json/json.h>

#include <boost/filesystem/path.hpp>

#include <map>
#include <string>

namespace osquery {

boost::filesystem::path const& getTestConfigDirectory();

// Get an example generate config with one static source name to JSON content.
std::map<std::string, std::string> getTestConfigMap(const std::string& file);

JSON getExamplePacksConfig();
JSON getUnrestrictedPack();
JSON getRestrictedPack();
JSON getPackWithDiscovery();
JSON getPackWithValidDiscovery();
JSON getPackWithFakeVersion();

} // namespace osquery
