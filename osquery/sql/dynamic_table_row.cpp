/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "dynamic_table_row.h"
#include "virtual_table.h"

#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/tryto.h>

namespace rj = rapidjson;

namespace osquery {

TableRows tableRowsFromQueryData(QueryData&& rows) {
  TableRows result;

  for (auto&& row : rows) {
    result.push_back(TableRowHolder(new DynamicTableRow(std::move(row))));
  }

  return result;
}

Status deserializeTableRows(const rj::Value& arr, TableRows& rows) {
  if (!arr.IsArray()) {
    return Status(1);
  }

  for (const auto& i : arr.GetArray()) {
    auto r = make_table_row();
    auto status = deserializeRow(i, r);
    if (!status.ok()) {
      return status;
    }
    rows.push_back(std::move(r));
  }
  return Status::success();
}

Status deserializeTableRowsJSON(const std::string& json, TableRows& rows) {
  auto doc = JSON::newArray();
  if (!doc.fromString(json) || !doc.doc().IsArray()) {
    return Status(1, "Cannot deserializing JSON");
  }

  return deserializeTableRows(doc.doc(), rows);
}

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
  return Status::success();
}

int DynamicTableRow::get_rowid(sqlite_int64 default_value,
                               sqlite_int64* pRowid) const {
  auto& current_row = this->row;
  auto rowid_it = current_row.find("rowid");
  if (rowid_it != current_row.end()) {
    const auto& rowid_text_field = rowid_it->second;

    auto exp = tryTo<long long>(rowid_text_field, 10);
    if (exp.isError()) {
      VLOG(1) << "Invalid rowid value returned " << exp.getError();
      return SQLITE_ERROR;
    }
    *pRowid = exp.take();

  } else {
    *pRowid = default_value;
  }
  return SQLITE_OK;
}

int DynamicTableRow::get_column(sqlite3_context* ctx,
                                sqlite3_vtab* vtab,
                                int col) {
  VirtualTable* pVtab = (VirtualTable*)vtab;
  auto& column_name = std::get<0>(pVtab->content->columns[col]);
  auto& type = std::get<1>(pVtab->content->columns[col]);
  if (pVtab->content->aliases.count(column_name)) {
    // Overwrite the aliased column with the type and name of the new column.
    type = std::get<1>(
        pVtab->content->columns[pVtab->content->aliases.at(column_name)]);
    column_name = std::get<0>(
        pVtab->content->columns[pVtab->content->aliases.at(column_name)]);
  }

  // Attempt to cast each xFilter-populated row/column to the SQLite type.
  const auto& value = row[column_name];
  if (this->row.count(column_name) == 0) {
    // Missing content.
    VLOG(1) << "Error " << column_name << " is empty";
    sqlite3_result_null(ctx);
  } else if (type == TEXT_TYPE || type == BLOB_TYPE) {
    sqlite3_result_text(
        ctx, value.c_str(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
  } else if (value.empty() &&
             (type == INTEGER_TYPE || type == BIGINT_TYPE ||
              type == UNSIGNED_BIGINT_TYPE || type == DOUBLE_TYPE)) {
    // Don't Log a casting error for a known type if the column row is empty
    sqlite3_result_null(ctx);
  } else if (type == INTEGER_TYPE) {
    auto afinite = tryTo<long>(value, 0);
    if (afinite.isError()) {
      VLOG(1) << "Error casting " << column_name << " (" << value
              << ") to INTEGER. " << afinite.getError();
      sqlite3_result_null(ctx);
    } else {
      sqlite3_result_int(ctx, afinite.take());
    }
  } else if (type == BIGINT_TYPE || type == UNSIGNED_BIGINT_TYPE) {
    auto afinite = tryTo<long long>(value, 0);
    if (afinite.isError()) {
      VLOG(1) << "Error casting " << column_name << " (" << value
              << ") to BIGINT. " << afinite.getError();
      sqlite3_result_null(ctx);
    } else {
      sqlite3_result_int64(ctx, afinite.take());
    }
  } else if (type == DOUBLE_TYPE) {
    char* end = nullptr;
    double afinite = strtod(value.c_str(), &end);
    if (end == nullptr || end == value.c_str() || *end != '\0') {
      VLOG(1) << "Error casting " << column_name << " (" << value
              << ") to DOUBLE";
      sqlite3_result_null(ctx);
    } else {
      sqlite3_result_double(ctx, afinite);
    }
  } else {
    LOG(ERROR) << "Error unknown column type " << column_name;
  }

  return SQLITE_OK;
}

Status DynamicTableRow::serialize(JSON& doc, rj::Value& obj) const {
  for (const auto& i : row) {
    doc.addRef(i.first, i.second, obj);
  }

  return Status::success();
}

TableRowHolder DynamicTableRow::clone() const {
  Row new_row = row;
  return TableRowHolder(new DynamicTableRow(std::move(new_row)));
}

} // namespace osquery
