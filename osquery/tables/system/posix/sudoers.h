/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#include <osquery/query.h>
#include <osquery/tables.h>

#include <string>

namespace osquery {
namespace tables {

void genSudoersFile(const std::string& filename,
                    unsigned int level,
                    QueryData& results);

QueryData genSudoers(QueryContext& context);

} // namespace tables
} // namespace osquery
