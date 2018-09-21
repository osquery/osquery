/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "query_data.h"

namespace rj = rapidjson;

namespace osquery {

Status serializeQueryData(const QueryData& q,
                          const ColumnNames& cols,
                          JSON& doc,
                          rj::Document& arr) {
  for (const auto& r : q) {
    auto row_obj = doc.getObject();
    auto status = serializeRow(r, cols, doc, row_obj);
    if (!status.ok()) {
      return status;
    }
    doc.push(row_obj, arr);
  }
  return Status();
}

Status serializeQueryDataJSON(const QueryData& q, std::string& json) {
  auto doc = JSON::newArray();

  ColumnNames cols;
  auto status = serializeQueryData(q, cols, doc, doc.doc());
  if (!status.ok()) {
    return status;
  }
  return doc.toString(json);
}

Status deserializeQueryData(const rj::Value& arr, QueryData& qd) {
  if (!arr.IsArray()) {
    return Status(1);
  }

  for (const auto& i : arr.GetArray()) {
    Row r;
    auto status = deserializeRow(i, r);
    if (!status.ok()) {
      return status;
    }
    qd.push_back(r);
  }
  return Status();
}

Status deserializeQueryData(const rj::Value& v, QueryDataSet& qd) {
  if (!v.IsArray()) {
    return Status(1, "JSON object was not an array");
  }

  for (const auto& i : v.GetArray()) {
    Row r;
    auto status = deserializeRow(i, r);
    if (!status.ok()) {
      return status;
    }
    qd.insert(std::move(r));
  }
  return Status();
}

Status deserializeQueryDataJSON(const std::string& json, QueryData& qd) {
  auto doc = JSON::newArray();
  if (!doc.fromString(json) || !doc.doc().IsArray()) {
    return Status(1, "Cannot deserializing JSON");
  }

  return deserializeQueryData(doc.doc(), qd);
}

Status deserializeQueryDataJSON(const std::string& json, QueryDataSet& qd) {
  rj::Document doc;
  if (doc.Parse(json.c_str()).HasParseError()) {
    return Status(1, "Error serializing JSON");
  }
  return deserializeQueryData(doc, qd);
}

bool addUniqueRowToQueryData(QueryData& q, const Row& r) {
  if (std::find(q.begin(), q.end(), r) != q.end()) {
    return false;
  }
  q.push_back(r);
  return true;
}

} // namespace osquery
