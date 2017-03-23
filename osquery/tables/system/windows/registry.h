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

const std::set<int> kRegistryStringTypes = {
    REG_SZ, REG_MULTI_SZ, REG_EXPAND_SZ};

/// Microsoft helper function for getting the contents of a registry key
void queryKey(const std::string& keyPath, QueryData& results);

/*
 * @brief Sanitize registry output strings which may not be null-terminated
 *
 * @note This will only modify the buffer if dataType is one if the values
 * in kRegistryStringTypes. Otherwise the buffer is unmodified.
 *
 * It's possible to incorrectly insert a a string into the registry such that
 * it ends up not being null-terminated, which can then cause buffer overflows
 * if the result is used without sanitizing
 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms724884(v=vs.85).aspx
 *
 * @param dataType The registry data type (i.e. REG_SZ)
 * @param dataBuff A buffer containing the registry data returned from
 * RegQueryValueEx
 * @param dataSize The length of dataBuff
 *
 * @return Success, unless either dataBuff is a nullptr and dataSize is nonzero,
 * or dataSize is 0 and dataBuff is not a nullptr.
 */
Status sanitizeRegistryStrings(const DWORD dataType,
                               BYTE* dataBuff,
                               DWORD dataSize);

void explodeRegistryPath(const std::string& path,
                         std::string& rHive,
                         std::string& rKey);
}
}
