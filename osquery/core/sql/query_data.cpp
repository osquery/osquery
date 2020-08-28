/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
  return Status::success();
}

Status serializeQueryData(const QueryDataTyped& q,
                          JSON& doc,
                          rj::Document& arr,
                          bool asNumeric) {
  for (const auto& r : q) {
    auto row_obj = doc.getObject();
    auto status = serializeRow(r, doc, row_obj, asNumeric);
    if (!status.ok()) {
      return status;
    }
    doc.push(row_obj, arr);
  }
  return Status::success();
}

Status serializeQueryDataJSON(const QueryData& q, JSON& doc) {
  doc = JSON::newArray();
  ColumnNames cols;
  auto status = serializeQueryData(q, cols, doc, doc.doc());
  return status;
}

Status serializeQueryDataJSON(const QueryData& q, std::string& json) {
  JSON doc;
  auto status = serializeQueryDataJSON(q, doc);

  if (!status.ok()) {
    return status;
  }

  return doc.toString(json);
}

Status serializeQueryDataJSON(const QueryDataTyped& q,
                              std::string& json,
                              bool asNumeric) {
  auto doc = JSON::newArray();

  auto status = serializeQueryData(q, doc, doc.doc(), asNumeric);
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
  return Status::success();
}

Status deserializeQueryData(const rj::Value& arr, QueryDataTyped& qd) {
  if (!arr.IsArray()) {
    return Status(1);
  }

  for (const auto& i : arr.GetArray()) {
    RowTyped r;
    auto status = deserializeRow(i, r);
    if (!status.ok()) {
      return status;
    }
    qd.push_back(r);
  }
  return Status::success();
}

Status deserializeQueryData(const rj::Value& v, QueryDataSet& qd) {
  if (!v.IsArray()) {
    return Status(1, "JSON object was not an array");
  }

  for (const auto& i : v.GetArray()) {
    RowTyped r;
    auto status = deserializeRow(i, r);
    if (!status.ok()) {
      return status;
    }
    qd.insert(std::move(r));
  }
  return Status::success();
}

Status deserializeQueryDataJSON(const JSON& doc, QueryData& qd) {
  if (!doc.doc().IsArray()) {
    return Status(1, "Cannot deserializing JSON");
  }

  return deserializeQueryData(doc.doc(), qd);
}

Status deserializeQueryDataJSON(const std::string& json, QueryData& qd) {
  auto doc = JSON::newArray();
  if (!doc.fromString(json)) {
    return Status(1, "Cannot deserializing JSON");
  }

  return deserializeQueryDataJSON(doc, qd);
}

Status deserializeQueryDataJSON(const std::string& json, QueryDataSet& qd) {
  rj::Document doc;
  if (doc.Parse(json.c_str()).HasParseError()) {
    return Status(1, "Error serializing JSON");
  }
  return deserializeQueryData(doc, qd);
}

bool addUniqueRowToQueryData(QueryDataTyped& q, const RowTyped& r) {
  if (std::find(q.begin(), q.end(), r) != q.end()) {
    return false;
  }
  q.push_back(r);
  return true;
}

} // namespace osquery
