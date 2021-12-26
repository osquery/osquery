/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
namespace osquery {
namespace tables {

// Registry path separator
const std::string kRegSep = "\\";

// Default registry key name
const std::string kDefaultRegName = "(Default)";

// Maximum recursive depth with searching the registry
const size_t kRegMaxRecursiveDepth = 32;

// Microsoft helper function for getting the contents of a registry key
Status queryKey(const std::string& keyPath, QueryData& results);

/*
 * @brief Helper function to query multiple registry keys
 *
 * @param keys a vector of registry keys to query using LIKE (caller adds %).
 * @param results a container to receive the results of the query
 */
Status queryMultipleRegistryKeys(const std::vector<std::string>& keys,
                                 QueryData& results);

/*
 * @brief Helper function to query multiple registry paths
 *
 * @param paths a vector of registry paths to query using LIKE (caller adds %).
 * @param results a container to receive the results of the query
 */
Status queryMultipleRegistryPaths(const std::vector<std::string>& paths,
                                  QueryData& results);

/*
 * @brief Get the name of a class from it's Class ID
 *
 * @param clsId the class ID, e.g. "{0000002F-0000-0000-C000-000000000046}"
 * @param rClsName Will be populated with the class name if successful
 * @return Failure if could not find  the class name in the registry, or
 * if one does not exist
 */
Status getClassName(const std::string& clsId, std::string& rClsName);

/*
 * @brief Get the executables associated with a Class ID
 *
 * This will return any executables (.dll, .exe, etc) associated with
 * the class ID in the registry. This includes the InProcServer32,
 * LocalServer32 and InProcHandler32 keys as well as the 16-bit versions.
 *
 * If the class exists in multiple locations (e.g. HKEY_USERS
 * and HKEY_LOCAL_MACHINE) then all entries will be returned.
 *
 * @param clsId The Class ID, e.g. "{0000002F-0000-0000-C000-000000000046}"
 * @param results Will be populated with a list of paths to executables
 * associated with the class.
 * @return Failure if there was a failure querying the registry or the
 * clsId doesn't exist on the system, otherwise success
 */
Status getClassExecutables(const std::string& clsId,
                           std::vector<std::string>& results);

/*
 * @brief Expand a globbing pattern into a set of registry keys to query.
 *
 * @param pattern The SQL globbing pattern, e.g.
 * 'HKEY_LOCAL_MACHINE\%\Microsoft' or 'HKEY_USERS\%\SOFTWARE\%%'
 * @param results A set that will be populated with all registry keys matching
 * the glob pattern. The set will be initially cleared.
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

/*
 * @brief Populate a set of registry keys with their subkeys
 *
 * For example, the key HKEY_LOCAL_MACHINE\SAM would produce a set with two keys
 * 'HKEY_LOCAL_MACHINE\SAM' and 'HKEY_LOCAL_MACHINE\SAM\SAM' if
 * (replaceKeys=false).
 *
 * @param rKeys A set that will be populated with all registry keys might have
 * subkeys
 * @param replaceKeys A boolean that controls whether the result set will be
 * initialized with the rKeys
 * @return Failure if all subkeys do not exist in registry, otherwise
 * success
 */
inline Status populateSubkeys(std::set<std::string>& rKeys,
                              bool replaceKeys = false);

} // namespace tables
} // namespace osquery
