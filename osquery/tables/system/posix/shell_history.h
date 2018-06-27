/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/query.h>
#include <osquery/tables.h>

#include <string>

namespace osquery {
namespace tables {

void genShellHistoryFromBashSessions(const std::string& uid,
                                     const std::string& directory,
                                     QueryData& results);
                                     
void genShellHistoryForUser(const std::string& uid,
                            const std::string& gid,
                            const std::string& directory,
                            QueryData& results);

QueryData genShellHistory(QueryContext& context);

} // namespace tables
} // namespace osquery
