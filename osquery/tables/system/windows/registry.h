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

const int kRegMaxRecursiveDepth = 32;

/// Microsoft helper function for getting the contents of a registry key
void queryKey(const std::string& keyPath, QueryData& results);

Status resolveRegistryGlobs(const std::string& pattern,
                            std::set<std::string>& results);

Status populateAllKeysRecursive(std::set<std::string>& rKeys,
                                int currDepth = 1,
                                int maxDepth = kRegMaxRecursiveDepth);

void appendSubkeyToKeys(const std::string& subkey,
                        std::set<std::string>& rKeys);

void replaceKeysWithSubkeys(std::set<std::string>& rKeys);

void maybeWarnLocalUsers(const std::set<std::string>& rKeys);

void explodeRegistryPath(const std::string& path,
                         std::string& rHive,
                         std::string& rKey);
}
}
