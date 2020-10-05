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

using ServiceNameMap = std::unordered_map<std::string, std::string>;

const static std::string kLocalSystem = "S-1-5-18";
const static std::string kLocalService = "S-1-5-19";
const static std::string kNetworkService = "S-1-5-20";

void parseSystemStoreString(LPCWSTR sysStoreW,
                            const std::string& storeLocation,
                            ServiceNameMap& service2sidCache,
                            std::string& serviceNameOrUserId,
                            std::string& sid,
                            std::string& storeName);

} // namespace tables
} // namespace osquery
