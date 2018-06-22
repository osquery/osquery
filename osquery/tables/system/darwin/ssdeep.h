/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/tables.h>

namespace osquery {
namespace tables {

void expandFSPathConstraints(QueryContext& context,
                             std::string path_column_name,
                             std::set<std::string>& paths);

void genSsdeepForFile(const std::string& path,
                      const std::string& dir,
                      QueryData& results);

QueryData genSsdeep(QueryContext& context);

}
}
