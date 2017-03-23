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

/// Microsoft helper function for getting the contents of a registry key
void queryKey(const std::string& keyPath, QueryData& results);


/* 
 * Sanitize any strings that were inserted into the registry incorrectly and
 * may contain non-null-terminated strings.
 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms724884(v=vs.85).aspx
 */
const std::set<int> kRegistryStringTypes = { REG_SZ, REG_MULTI_SZ, REG_EXPAND_SZ };

Status sanitizeRegistryStrings(const DWORD dataType, BYTE* dataBuff, DWORD dataSize);

void explodeRegistryPath(const std::string& path,
                         std::string& rHive,
                         std::string& rKey);
}
}
