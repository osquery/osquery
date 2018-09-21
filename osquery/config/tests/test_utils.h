/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <osquery/utils/json.h>

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
