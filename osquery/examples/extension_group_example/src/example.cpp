/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
