/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/query.h>
#include <osquery/tables.h>

#include <string>

namespace osquery {
namespace tables {

QueryData getKnownHostsKeys(QueryContext& context);

namespace impl {

void genSSHkeysForHosts(const std::string& uid,
                        const std::string& gid,
                        const std::string& directory,
                        QueryData& results);

} // namespace impl

} // namespace tables
} // namespace osquery
