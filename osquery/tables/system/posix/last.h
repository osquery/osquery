/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/query.h>
#include <osquery/tables.h>

#include <utmpx.h>

namespace osquery {
namespace tables {

QueryData genLastAccess(QueryContext& context);

namespace impl {

void genLastAccessForRow(const utmpx& ut, QueryData& results);

} // namespace impl

} // namespace tables
} // namespace osquery
