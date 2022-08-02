/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/query.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/worker/logging/glog/glog_logger.h>

#include <string>

namespace osquery {
namespace tables {

void genSSHkeysForUser(const std::string& uid,
                       const std::string& gid,
                       const std::string& directory,
                       QueryData& results,
                       Logger& logger);

QueryData getAuthorizedKeys(QueryContext& context);

} // namespace tables
} // namespace osquery
