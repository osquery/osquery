/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/json/json.h>

#include <boost/filesystem/path.hpp>

#include <map>
#include <string>

namespace osquery {

boost::filesystem::path const& getTestConfigDirectory();
boost::filesystem::path const& getTestHelperScriptsDirectory();

// Get an example generate config with one static source name to JSON content.
std::map<std::string, std::string> getTestConfigMap(const std::string& file);

JSON getExamplePacksConfig();
JSON getUnrestrictedPack();
JSON getRestrictedPack();
JSON getPackWithDiscovery();
JSON getPackWithValidDiscovery();
JSON getPackWithFakeVersion();

} // namespace osquery
