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

#include <utmpx.h>

namespace osquery {
namespace tables {

QueryData genLastAccess(QueryContext& context);

namespace impl {

void genLastAccessForRow(const utmpx& ut, QueryData& results);

} // namespace impl

} // namespace tables
} // namespace osquery
