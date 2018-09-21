/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "row.h"

namespace rj = rapidjson;

namespace osquery {

Status serializeRow(const Row& r,
                    const ColumnNames& cols,
                    JSON& doc,
                    rj::Value& obj) {
  if (cols.empty()) {
    for (const auto& i : r) {
      doc.addRef(i.first, i.second, obj);
    }
  } else {
    for (const auto& c : cols) {
      auto i = r.find(c);
      if (i != r.end()) {
        doc.addRef(c, i->second, obj);
      }
    }
  }

  return Status();
}

Status serializeRowJSON(const Row& r, std::string& json) {
  auto doc = JSON::newObject();

  // An empty column list will traverse the row map.
  ColumnNames cols;
  auto status = serializeRow(r, cols, doc, doc.doc());
  if (!status.ok()) {
    return status;
  }
  return doc.toString(json);
}

Status deserializeRow(const rj::Value& doc, Row& r) {
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

Status deserializeRowJSON(const std::string& json, Row& r) {
  auto doc = JSON::newObject();
  if (!doc.fromString(json) || !doc.doc().IsObject()) {
    return Status(1, "Cannot deserializing JSON");
  }
  return deserializeRow(doc.doc(), r);
}



} // namespace osquery
