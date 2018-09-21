/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "diff_results.h"

namespace rj = rapidjson;

namespace osquery {

Status serializeDiffResults(const DiffResults& d,
                            const ColumnNames& cols,
                            JSON& doc,
                            rj::Document& obj) {
  // Serialize and add "removed" first.
  // A property tree is somewhat ordered, this provides a loose contract to
  // the logger plugins and their aggregations, allowing them to parse chunked
  // lines. Note that the chunking is opaque to the database functions.
  auto removed_arr = doc.getArray();
  auto status = serializeQueryData(d.removed, cols, doc, removed_arr);
  if (!status.ok()) {
    return status;
  }
  doc.add("removed", removed_arr, obj);

  auto added_arr = doc.getArray();
  status = serializeQueryData(d.added, cols, doc, added_arr);
  if (!status.ok()) {
    return status;
  }
  doc.add("added", added_arr, obj);
  return Status();
}

Status serializeDiffResultsJSON(const DiffResults& d, std::string& json) {
  auto doc = JSON::newObject();

  ColumnNames cols;
  auto status = serializeDiffResults(d, cols, doc, doc.doc());
  if (!status.ok()) {
    return status;
  }
  return doc.toString(json);
}

DiffResults diff(QueryDataSet& old, QueryData& current) {
  DiffResults r;

  for (auto& i : current) {
    auto item = old.find(i);
    if (item != old.end()) {
      old.erase(item);
    } else {
      r.added.push_back(i);
    }
  }

  for (auto& i : old) {
    r.removed.push_back(std::move(i));
  }

  return r;
}

} // namespace osquery
