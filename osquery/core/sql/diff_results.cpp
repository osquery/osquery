/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "diff_results.h"

namespace rj = rapidjson;

namespace osquery {

Status serializeDiffResults(const DiffResults& d,
                            JSON& doc,
                            rj::Document& obj,
                            bool asNumeric) {
  // Serialize and add "removed" first.
  // A property tree is somewhat ordered, this provides a loose contract to
  // the logger plugins and their aggregations, allowing them to parse chunked
  // lines. Note that the chunking is opaque to the database functions.
  auto removed_arr = doc.getArray();
  auto status = serializeQueryData(d.removed, doc, removed_arr, asNumeric);
  if (!status.ok()) {
    return status;
  }
  doc.add("removed", removed_arr, obj);

  auto added_arr = doc.getArray();
  status = serializeQueryData(d.added, doc, added_arr, asNumeric);
  if (!status.ok()) {
    return status;
  }
  doc.add("added", added_arr, obj);
  return Status::success();
}

Status serializeDiffResultsJSON(const DiffResults& d,
                                std::string& json,
                                bool asNumeric) {
  auto doc = JSON::newObject();

  ColumnNames cols;
  auto status = serializeDiffResults(d, doc, doc.doc(), asNumeric);
  if (!status.ok()) {
    return status;
  }
  return doc.toString(json);
}

DiffResults diff(QueryDataSet& old, QueryDataTyped& current) {
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
