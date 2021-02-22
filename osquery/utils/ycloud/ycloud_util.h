/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/json/json.h>
#include <osquery/utils/status/status.h>

namespace osquery {
std::string getYCloudKey(JSON& doc, const std::string& key);
std::string getYCloudSshKey(JSON& doc);
std::string getSerialPortEnabled(JSON& doc);
std::tuple<std::string, std::string> getFolderIdAndZoneFromZoneField(
    const std::string& zone);
Status fetchYCloudMetadata(JSON& doc, const std::string& endpoint);
} // namespace osquery