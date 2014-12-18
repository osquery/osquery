/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifndef OSQUERY_TABLES_SYSTEM_FIREWALL_H
#define OSQUERY_TABLES_SYSTEM_FIREWALL_H

#include <map>
#include <string>

#include <boost/property_tree/ptree.hpp>

#include <osquery/database/results.h>

namespace osquery {
namespace tables {

// Given a property tree of the parsed content of com.apple.alf.plist,
// parseALFExceptionsTree parses out the "exceptions" key
osquery::QueryData parseALFExceptionsTree(
    const boost::property_tree::ptree& tree);

// Given a property tree of the parsed content of com.apple.alf.plist,
// parseALFExplicitAuthsTree parses out the "explicitauth" key
osquery::QueryData parseALFExplicitAuthsTree(
    const boost::property_tree::ptree& tree);

// Given a property tree of the parsed content of com.apple.alf.plist,
// parseALFServicesTree parses out the services which exist under the
// "firewall" key
osquery::QueryData parseALFServicesTree(
    const boost::property_tree::ptree& tree);

// Given a property tree of the parsed content of com.apple.alf.plist,
// parseALFTree parses out the top level string and int keys
osquery::QueryData parseALFTree(const boost::property_tree::ptree& tree);

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

#endif /* OSQUERY_TABLES_SYSTEM_FIREWALL_H */
