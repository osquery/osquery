/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "dynamic_table_row.h"

namespace rj = rapidjson;

namespace osquery {

Status deserializeRow(const rj::Value& doc, DynamicTableRowHolder& r) {
  if (!doc.IsObject()) {
    return Status(1);
  }

  for (const auto& i : doc.GetObject()) {
    std::string name(i.name.GetString());
    if (!name.empty() && i.value.IsString()) {
      r[name] = i.value.GetString();
    }
  }
  return Status();
}

} // namespace osquery
