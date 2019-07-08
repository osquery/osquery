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

#include <osquery/core.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

const static std::string kLocalSystem = "S-1-5-18";
const static std::string kLocalService = "S-1-5-19";
const static std::string kNetworkService = "S-1-5-20";

void parseSystemStoreString(LPCWSTR sysStoreW,
                            const std::string& storeLocation,
                            std::string& serviceNameOrUserId,
                            std::string& sid,
                            std::string& storeName);

} // namespace tables
} // namespace osquery