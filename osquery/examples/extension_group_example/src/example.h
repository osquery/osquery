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

#include <osquery/sdk.h>
#include <osquery/system.h>

namespace osquery {
class ExampleTable : public TablePlugin {
 private:
  TableColumns columns() const;
  QueryData generate(QueryContext& request);
};
} // namespace osquery
