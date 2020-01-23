/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/sdk.h>
#include <osquery/system.h>

namespace osquery {
class ExampleTable : public TablePlugin {
 private:
  TableColumns columns() const;
  QueryData generate(QueryContext& request);
};
} // namespace osquery
