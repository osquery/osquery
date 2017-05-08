/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <osquery/core.h>
#include <osquery/tables.h>
namespace osquery {
namespace tables {

// Registry path separator
const std::string kRegSep = "\\";

// Default registry key name
const std::string kDefaultRegName = "(Default)";

// Maximum recursive depth with searching the registry
const size_t kRegMaxRecursiveDepth = 32;

/// Microsoft helper function for getting the contents of a registry key
Status queryKey(const std::string& keyPath, QueryData& results);

/*
 * @brief Expand a globbing pattern into a set of registry keys to
 * query
 *
 * @param pattern The SQL globbing pattern, e.g.
 * 'HKEY_LOCAL_MACHINE\%\Microsoft' or 'HKEY_USERS\%\SOFTWARE\%%'
 * @param results A set that will be populated with all registry keys matching
 * the glob pattern
 * @return Failure if the max recursive depth is reached, otherwise success
 */
Status expandRegistryGlobs(const std::string& pattern,
                           std::set<std::string>& results);

/*
 * @brief Explode a registry path into a HIVE and KEY
 *
 * For example, if the path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft' is provided,
 * the HIVE is 'HKEY_LOCAL_MACHINE' and the key is 'SOFTWARE\Microsoft'.
 *
 * @param path The full registry path, e.g.
 * 'HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT'
 * @param rHive a string that will be populated with the HIVE
 * @param rKey a string that will be populated with the KEY
 *
 */
inline void explodeRegistryPath(const std::string& path,
                                std::string& rHive,
                                std::string& rKey);

/*
 * @brief Given an HKEY_USERS key, extract the username associated with the key
 *
 * For example, the key HKEY_USERS\S-1-5-19\.. would produce 'LOCAL SERVICE'.
 *
 * @param key The registry key, must start with HKEY_USERS and have a depth
 * of at least 2
 * @param rUsername A string that will be populated with the username if
 * successful
 * @return Failure if a username cannot be extracted from the key, otherwise
 * success
 */
Status getUsernameFromKey(const std::string& key, std::string& rUsername);
}
}
