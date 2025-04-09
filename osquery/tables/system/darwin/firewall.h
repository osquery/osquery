/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <string>

#include <boost/property_tree/ptree.hpp>

#include <osquery/database/database.h>
#include <osquery/sql/sql.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

// Given a property tree of the parsed content of com.apple.alf.plist,
// parseALFExceptionsTree parses out the "exceptions" key
osquery::QueryData parseALFExceptionsTree(const pt::ptree& tree);

// Currently, on macOS 15+ osquery supports the following 'alf' columns:
//
// 'global_state', 'stealth_enabled', 'logging_enabled', and 'version'.
// These columns are populated from information gathered from system_profiler's
// "SPFirewallDataType".
//
// 'alf' columns that are not supported (returned empty) on macOS 15+:
//
//  - 'allow_signed_enabled': (As of September 24th, 2024) This setting is only
//  exposed through
//    executing '/usr/libexec/ApplicationFirewall/socketfilterfw
//    --getallowsigned'.
//  - 'logging_option': Quote from https://support.apple.com/en-jo/121011: "The
//  EnableLogging and
//    LoggingOption keys in the Firewall payload are deprecated and no longer
//    necessary. Application Firewall logging is increased by default for the
//    socketfilterfw process."
//  - 'firewall_unload': This does not seem available on system_profiler's
//  "SPFirewallDataType"
//    or the socketfilterfw command.
osquery::QueryData genALFFromSystemProfiler();

// Currently, on macOS 15+:
//  - `alf_exceptions` returns only a subset of the exceptions (only signed apps
//  it seems). The full list of exceptions can be gathered only by executing
//  `/usr/libexec/ApplicationFirewall/socketfilterfw --listapps`.
//  - `path` contains the bundle identifier and not the file path.
//  - The column `state` currently has two values "0" and "2". It attempts to
//  follow the semantic value as macOS < 15, "0" means "allow incoming
//  connections" and "2" means "block incoming connections".
osquery::QueryData genALFExceptionsFromSystemProfiler();

// Given a property tree of the parsed content of com.apple.alf.plist,
// parseALFExplicitAuthsTree parses out the "explicitauth" key
osquery::QueryData parseALFExplicitAuthsTree(const pt::ptree& tree);

// Given a property tree of the parsed content of com.apple.alf.plist,
// parseALFTree parses out the top level string and int keys
osquery::QueryData parseALFTree(const pt::ptree& tree);

// kALFPlistPath is the path of the com.apple.alf.plist path
extern const std::string kALFPlistPath;

// kTopLevelIntKeys is a map of keys and columns which are used while parsing
// in the function parseALFTree
extern const std::map<std::string, std::string> kTopLevelIntKeys;

// kTopLevelStringKeys is a map of keys and columns which are used while
// parsing in the function parseALFTree
extern const std::map<std::string, std::string> kTopLevelStringKeys;
} // namespace tables
} // namespace osquery
