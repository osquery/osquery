/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "example.h"

namespace osquery {
TableColumns ExampleTable::columns() const {
  return {
      std::make_tuple("example_text", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("example_integer", INTEGER_TYPE, ColumnOptions::DEFAULT),
  };
}

QueryData ExampleTable::generate(QueryContext& request) {
  static_cast<void>(request);

  Row r;
  r["example_text"] = "example";
  r["example_integer"] = INTEGER(1);

  return {r};
}
} // namespace osquery
