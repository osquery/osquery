/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
