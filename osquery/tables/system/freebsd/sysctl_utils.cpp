/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

//#include <sys/sysctl.h>

#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/tables/system/sysctl_utils.h"

namespace osquery {
namespace tables {

void genControlInfo(int* oid,
                    size_t oid_size,
                    QueryData& results,
                    const std::map<std::string, std::string>& config) {
}

void genControlInfoFromName(const std::string& name, QueryData& results,
                    const std::map<std::string, std::string>& config) {
}

void genAllControls(QueryData& results,
                    const std::map<std::string, std::string>& config,
                    const std::string& subsystem) {
}
}
}
