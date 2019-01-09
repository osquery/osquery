/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "table_row.h"
#include "dynamic_table_row.h"

namespace osquery {

TableRowHolder::TableRowHolder() = default;

TableRowHolder::TableRowHolder(DynamicTableRow* row) : unique_ptr(row) {}

TableRowHolder::TableRowHolder(TableRowHolder&& other) = default;

TableRowHolder& TableRowHolder::operator=(TableRowHolder&& other) = default;

TableRowHolder::~TableRowHolder() = default;

TableRowHolder TableRowHolder::clone() const {
  return TableRowHolder(new DynamicTableRow((**this)));
}

} // namespace osquery
