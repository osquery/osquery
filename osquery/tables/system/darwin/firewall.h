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

#include <map>
#include <string>

#include <boost/property_tree/ptree.hpp>

#include <osquery/database.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

// Given a property tree of the parsed content of com.apple.alf.plist,
// parseALFExceptionsTree parses out the "exceptions" key
osquery::QueryData parseALFExceptionsTree(const pt::ptree& tree);

// Given a property tree of the parsed content of com.apple.alf.plist,
// parseALFExplicitAuthsTree parses out the "explicitauth" key
osquery::QueryData parseALFExplicitAuthsTree(const pt::ptree& tree);

// Given a property tree of the parsed content of com.apple.alf.plist,
// parseALFServicesTree parses out the services which exist under the
// "firewall" key
osquery::QueryData parseALFServicesTree(const pt::ptree& tree);

// Given a property tree of the parsed content of com.apple.alf.plist,
// parseALFTree parses out the top level string and int keys
osquery::QueryData parseALFTree(const pt::ptree& tree);

// kALFPlistPath is the path of the com.apple.alf.plist path
extern const std::string kALFPlistPath;

// kFirewallTreeKeys is a map of keys and columns which are used while parsing
// in the function parseALFServicesTree
extern const std::map<std::string, std::string> kFirewallTreeKeys;

// kTopLevelIntKeys is a map of keys and columns which are used while parsing
// in the function parseALFTree
extern const std::map<std::string, std::string> kTopLevelIntKeys;

// kTopLevelStringKeys is a map of keys and columns which are used while
// parsing in the function parseALFTree
extern const std::map<std::string, std::string> kTopLevelStringKeys;
}
}
