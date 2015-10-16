/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/logger.h>

#include "osquery/sql/virtual_table.h"

namespace osquery {
namespace tables {

int xOpen(sqlite3_vtab *pVTab, sqlite3_vtab_cursor **ppCursor) {
  int rc = SQLITE_NOMEM;
  BaseCursor *pCur = new BaseCursor;

  if (pCur) {
    memset(pCur, 0, sizeof(BaseCursor));
    *ppCursor = (sqlite3_vtab_cursor *)pCur;
    rc = SQLITE_OK;
  }

  return rc;
}

int xClose(sqlite3_vtab_cursor *cur) {
  BaseCursor *pCur = (BaseCursor *)cur;

  delete pCur;
  return SQLITE_OK;
}

int xEof(sqlite3_vtab_cursor *cur) {
  BaseCursor *pCur = (BaseCursor *)cur;
  auto *pVtab = (VirtualTable *)cur->pVtab;

  if (pCur->row >= pVtab->content->n) {
    // If the requested row exceeds the size of the row set then all rows
    // have been visited, clear the data container.
    QueryData().swap(pVtab->content->data);
    return true;
  }
  return false;
}

int xDestroy(sqlite3_vtab *p) {
  auto *pVtab = (VirtualTable *)p;
  delete pVtab->content;
  delete pVtab;
  return SQLITE_OK;
}

int xNext(sqlite3_vtab_cursor *cur) {
  BaseCursor *pCur = (BaseCursor *)cur;
  pCur->row++;
  return SQLITE_OK;
}

int xRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid) {
  const BaseCursor *pCur = (BaseCursor *)cur;
  *pRowid = pCur->row;
  return SQLITE_OK;
}

int xCreate(sqlite3 *db,
            void *pAux,
            int argc,
            const char *const *argv,
            sqlite3_vtab **ppVtab,
            char **pzErr) {
  auto *pVtab = new VirtualTable;

  if (!pVtab || argc == 0 || argv[0] == nullptr) {
    //  return SQLITE_NOMEM;  // memory leak
  }

  memset(pVtab, 0, sizeof(VirtualTable));
  pVtab->content = new VirtualTableContent;

  PluginResponse response;
  pVtab->content->name = std::string(argv[0]);

  // Get the table column information.
  auto status = Registry::call(
      "table", pVtab->content->name, {{"action", "columns"}}, response);
  if (!status.ok() || response.size() == 0) {
    // return SQLITE_ERROR;  // memory leak
  }

  auto statement =
      "CREATE TABLE " + pVtab->content->name + columnDefinition(response);
  int rc = sqlite3_declare_vtab(db, statement.c_str());
  if (rc != SQLITE_OK) {
    // return rc;  // memory leaks
  }

  if (!status.ok() || response.size() == 0) {
    // return SQLITE_ERROR;  // memory leak
  }

  for (const auto &column : response) {
    pVtab->content->columns.push_back(
        std::make_pair(column.at("name"), column.at("type")));
  }

  *ppVtab = (sqlite3_vtab *)pVtab;
  return rc;
}

int xColumn(sqlite3_vtab_cursor *cur, sqlite3_context *ctx, int col) {
  const BaseCursor *pCur = (BaseCursor *)cur;
  const auto *pVtab = (VirtualTable *)cur->pVtab;

  if (col >= pVtab->content->columns.size()) {
    // Requested column index greater than column set size.
    return SQLITE_ERROR;
  }

  const auto &column_name = pVtab->content->columns[col].first;
  const auto &type = pVtab->content->columns[col].second;
  if (pCur->row >= pVtab->content->data.size()) {
    // Request row index greater than row set size.
    return SQLITE_ERROR;
  }

  // Attempt to cast each xFilter-populated row/column to the SQLite type.
  const auto &value = pVtab->content->data[pCur->row][column_name];
  if (type == "TEXT") {
    sqlite3_result_text(ctx, value.c_str(), value.size(), SQLITE_STATIC);
  } else if (type == "INTEGER") {
    char *end = nullptr;
    long int afinite = strtol(value.c_str(), &end, 10);
    if (end == nullptr || end == value.c_str() || *end != '\0' ||
        ((afinite == LONG_MIN || afinite == LONG_MAX) && errno == ERANGE) ||
        afinite < INT_MIN || afinite > INT_MAX) {
      afinite = -1;
      VLOG(1) << "Error casting " << column_name << " (" << value
              << ") to INTEGER";
    }
    sqlite3_result_int(ctx, (int)afinite);
  } else if (type == "BIGINT") {
    char *end = nullptr;
    long long int afinite = strtoll(value.c_str(), &end, 10);
    if (end == nullptr || end == value.c_str() || *end != '\0' ||
        ((afinite == LLONG_MIN || afinite == LLONG_MAX) && errno == ERANGE)) {
      afinite = -1;
      VLOG(1) << "Error casting " << column_name << " (" << value
              << ") to BIGINT";
    }
    sqlite3_result_int64(ctx, afinite);
  } else if (type == "DOUBLE") {
    char *end = nullptr;
    double afinite = strtod(value.c_str(), &end);
    if (end == nullptr || end == value.c_str() || *end != '\0') {
      afinite = 0;
      VLOG(1) << "Error casting " << column_name << " (" << value
              << ") to DOUBLE";
    }
    sqlite3_result_double(ctx, afinite);
  }

  return SQLITE_OK;
}

static int xBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo) {
  auto *pVtab = (VirtualTable *)tab;
  ConstraintSet().swap(pVtab->content->constraints);

  int expr_index = 0;
  int cost = 0;
  for (size_t i = 0; i < pIdxInfo->nConstraint; ++i) {
    if (!pIdxInfo->aConstraint[i].usable) {
      // A higher cost less priority, prefer more usable query constraints.
      cost += 10;
      // TODO: OR is not usable.
      continue;
    }

    const auto &name =
        pVtab->content->columns[pIdxInfo->aConstraint[i].iColumn].first;
    pVtab->content->constraints.push_back(
        std::make_pair(name, Constraint(pIdxInfo->aConstraint[i].op)));
    pIdxInfo->aConstraintUsage[i].argvIndex = ++expr_index;
  }

  pIdxInfo->estimatedCost = cost;
  return SQLITE_OK;
}

static int xFilter(sqlite3_vtab_cursor *pVtabCursor,
                   int idxNum,
                   const char *idxStr,
                   int argc,
                   sqlite3_value **argv) {
  BaseCursor *pCur = (BaseCursor *)pVtabCursor;
  auto *pVtab = (VirtualTable *)pVtabCursor->pVtab;

  pCur->row = 0;
  pVtab->content->n = 0;
  QueryContext context;

  for (size_t i = 0; i < pVtab->content->columns.size(); ++i) {
    // Set the column affinity for each optional constraint list.
    // There is a separate list for each column name.
    context.constraints[pVtab->content->columns[i].first].affinity =
        pVtab->content->columns[i].second;
  }

  // Iterate over every argument to xFilter, filling in constraint values.
  for (size_t i = 0; i < argc; ++i) {
    auto expr = (const char *)sqlite3_value_text(argv[i]);
    if (expr == nullptr) {
      // SQLite did not expose the expression value.
      continue;
    }
    // Set the expression from SQLite's now-populated argv.
    pVtab->content->constraints[i].second.expr = std::string(expr);
    // Add the constraint to the column-sorted query request map.
    context.constraints[pVtab->content->constraints[i].first].add(
        pVtab->content->constraints[i].second);
  }

  // Reset the virtual table contents.
  pVtab->content->data.clear();

  // Generate the row data set.
  PluginRequest request = {{"action", "generate"}};
  TablePlugin::setRequestFromContext(context, request);
  Registry::call("table", pVtab->content->name, request, pVtab->content->data);

  // Set the number of rows.
  pVtab->content->n = pVtab->content->data.size();

  return SQLITE_OK;
}
}

Status attachTableInternal(const std::string &name,
                           const std::string &statement,
                           sqlite3 *db) {
  if (SQLiteDBManager::isDisabled(name)) {
    VLOG(0) << "Table " << name << " is disabled, not attaching";
    return Status(0, getStringForSQLiteReturnCode(0));
  }

  // A static module structure does not need specific logic per-table.
  // clang-format off
  static sqlite3_module module = {
      0,
      tables::xCreate,
      tables::xCreate,
      tables::xBestIndex,
      tables::xDestroy,
      tables::xDestroy,
      tables::xOpen,
      tables::xClose,
      tables::xFilter,
      tables::xNext,
      tables::xEof,
      tables::xColumn,
      tables::xRowid,
  };
  // clang-format on

  // Note, if the clientData API is used then this will save a registry call
  // within xCreate.
  int rc = sqlite3_create_module(db, name.c_str(), &module, 0);
  if (rc == SQLITE_OK || rc == SQLITE_MISUSE) {
    auto format =
        "CREATE VIRTUAL TABLE temp." + name + " USING " + name + statement;
    rc = sqlite3_exec(db, format.c_str(), nullptr, nullptr, 0);
  } else {
    LOG(ERROR) << "Error attaching table: " << name << " (" << rc << ")";
  }
  return Status(rc, getStringForSQLiteReturnCode(rc));
}

Status detachTableInternal(const std::string &name, sqlite3 *db) {
  auto format = "DROP TABLE IF EXISTS temp." + name;
  int rc = sqlite3_exec(db, format.c_str(), nullptr, nullptr, 0);
  if (rc != SQLITE_OK) {
    LOG(ERROR) << "Error detaching table: " << name << " (" << rc << ")";
  }

  return Status(rc, getStringForSQLiteReturnCode(rc));
}

void attachVirtualTables(sqlite3 *db) {
  PluginResponse response;
  for (const auto &name : Registry::names("table")) {
    // Column information is nice for virtual table create call.
    auto status =
        Registry::call("table", name, {{"action", "columns"}}, response);
    if (status.ok()) {
      auto statement = columnDefinition(response);
      attachTableInternal(name, statement, db);
    }
  }
}
}
