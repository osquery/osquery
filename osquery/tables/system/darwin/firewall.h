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
}
}
