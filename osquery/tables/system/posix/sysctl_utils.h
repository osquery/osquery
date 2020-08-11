/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <sys/sysctl.h>

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

#define CTL_MAX_VALUE 128

#ifndef CTL_DEBUG_MAXID
#define CTL_DEBUG_MAXID (CTL_MAXNAME * 2)
#endif

std::string stringFromMIB(const int* oid, size_t oid_size);

/// Must be implemented by the platform.
void genAllControls(QueryData& results,
                    const std::map<std::string, std::string>& config,
                    const std::string& subsystem);

/// Must be implemented by the platform.
void genControlInfo(int* oid,
                    size_t oid_size,
                    QueryData& results,
                    const std::map<std::string, std::string>& config);

/// Must be implemented by the platform.
void genControlInfoFromName(const std::string& name,
                            QueryData& results,
                            const std::map<std::string, std::string>& config);
}
}
