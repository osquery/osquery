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

#include <string>

namespace osquery {
namespace tables {

void genSudoersFile(const std::string& filename,
                    unsigned int level,
                    QueryData& results);

QueryData genSudoers(QueryContext& context);

} // namespace tables
} // namespace osquery
