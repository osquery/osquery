/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/worker/logging/logger.h>

#include <map>
#include <string>

namespace osquery {
namespace tables {

const std::string kPath = "/etc";
const std::string kOSRelease = "os-release";
const std::string kRedhatRelease = "redhat-release";
const std::string kGentooRelease = "gentoo-release";
const std::string kOracleRelease = "oracle-release";

const std::map<std::string, std::string> kOSReleaseColumns = {
    {"NAME", "name"},
    {"VERSION", "version"},
    {"BUILD_ID", "build"},
    {"ID", "platform"},
    {"ID_LIKE", "platform_like"},
    {"VERSION_CODENAME", "codename"},
    {"VERSION_ID", "_id"},
};

void genOSRelease(const std::string& path, Row& r);
QueryData genOSVersionImpl(QueryContext& context, Logger& logger);
QueryData genOSVersion(QueryContext& context);
std::string getMachineArchitecture();
void parseOSVersion(const std::string& path, Row& r);

} // namespace tables
} // namespace osquery
