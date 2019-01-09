/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include "row.h"

namespace osquery {

using DynamicTableRow = Row;

// Right now this is an alias for Row; it is going to become an interface
// with multiple implementations
using TableRow = Row;

// Right now this is a unique_ptr with a clone function added. clone will be
// moving to the TableRow interface, and this will become a unique_ptr<TableRow>
class TableRowHolder : public std::unique_ptr<DynamicTableRow> {
 public:
  TableRowHolder();
  TableRowHolder(DynamicTableRow* row);
  ~TableRowHolder();

  TableRowHolder(const TableRowHolder& other) = delete;
  TableRowHolder& operator=(const TableRowHolder& other) = delete;

  TableRowHolder(TableRowHolder&& other);
  TableRowHolder& operator=(TableRowHolder&& other);

  TableRowHolder clone() const;
};

} // namespace osquery
