/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <map>

#include <stdio.h>

#include <sqlite3.h>

#include <osquery/registry.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

/**
 * @brief osquery cursor object.
 *
 * Only used in the SQLite virtual table module methods.
 */
struct base_cursor {
  /// SQLite virtual table cursor.
  sqlite3_vtab_cursor base;
  /// Current cursor position.
  int row;
};

/**
 * @brief osquery virtual table object
 *
 * Only used in the SQLite virtual table module methods.
 * This adds each table plugin class to the state tracking in SQLite.
 */
template <class TABLE_PLUGIN>
struct x_vtab {
  sqlite3_vtab base;
  /// To get custom functionality from SQLite virtual tables, add a struct.
  TABLE_PLUGIN *pContent;
};

int xOpen(sqlite3_vtab *pVTab, sqlite3_vtab_cursor **ppCursor);

int xClose(sqlite3_vtab_cursor *cur);

int xNext(sqlite3_vtab_cursor *cur);

int xRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid);

int xEof(sqlite3_vtab_cursor *cur);

template <typename T>
int xCreate(sqlite3 *db,
            void *pAux,
            int argc,
            const char *const *argv,
            sqlite3_vtab **ppVtab,
            char **pzErr) {
  auto *pVtab = new x_vtab<T>;

  if (!pVtab) {
    return SQLITE_NOMEM;
  }

  memset(pVtab, 0, sizeof(x_vtab<T>));
  auto *pContent = pVtab->pContent = new T;
  auto create = pContent->statement(pContent->name, pContent->columns);
  int rc = sqlite3_declare_vtab(db, create.c_str());

  *ppVtab = (sqlite3_vtab *)pVtab;
  return rc;
}

int xDestroy(sqlite3_vtab *p);

template <typename T>
int xColumn(sqlite3_vtab_cursor *cur, sqlite3_context *ctx, int col) {
  base_cursor *pCur = (base_cursor *)cur;
  auto *pContent = ((x_vtab<T> *)cur->pVtab)->pContent;

  if (col >= pContent->columns.size()) {
    return SQLITE_ERROR;
  }

  const auto &column_name = pContent->columns[col].first;
  const auto &type = pContent->columns[col].second;
  if (pCur->row >= pContent->data[column_name].size()) {
    return SQLITE_ERROR;
  }

  const auto &value = pContent->data[column_name][pCur->row];
  if (type == "TEXT") {
    sqlite3_result_text(ctx, value.c_str(), -1, nullptr);
  } else if (type == "INTEGER") {
    int afinite;
    try {
      afinite = boost::lexical_cast<int>(value);
    } catch (const boost::bad_lexical_cast &e) {
      afinite = -1;
      LOG(WARNING) << "Error casting " << column_name << " (" << value
                   << ") to INTEGER";
    }
    sqlite3_result_int(ctx, afinite);
  } else if (type == "BIGINT") {
    long long int afinite;
    try {
      afinite = boost::lexical_cast<long long int>(value);
    } catch (const boost::bad_lexical_cast &e) {
      afinite = -1;
      LOG(WARNING) << "Error casting " << column_name << " (" << value
                   << ") to BIGINT";
    }
    sqlite3_result_int64(ctx, afinite);
  }

  return SQLITE_OK;
}

template <typename T>
static int xBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo) {
  auto *pContent = ((x_vtab<T> *)tab)->pContent;

  int expr_index = 0;
  int cost = 0;
  for (size_t i = 0; i < pIdxInfo->nConstraint; ++i) {
    if (!pIdxInfo->aConstraint[i].usable) {
      // A higher cost less priority, prefer more usable query constraints.
      cost += 10;

      // TODO: OR is not usable.
      continue;
    }

    const auto& name =
        pContent->columns[pIdxInfo->aConstraint[i].iColumn].first;
    pContent->constraints.push_back(
        std::make_pair(name, Constraint(pIdxInfo->aConstraint[i].op)));
    pIdxInfo->aConstraintUsage[i].argvIndex = ++expr_index;
  }

  pIdxInfo->estimatedCost = cost;
  return SQLITE_OK;
}

template <typename T>
static int xFilter(sqlite3_vtab_cursor *pVtabCursor,
                   int idxNum,
                   const char *idxStr,
                   int argc,
                   sqlite3_value **argv) {
  base_cursor *pCur = (base_cursor *)pVtabCursor;
  auto *pContent = ((x_vtab<T> *)pVtabCursor->pVtab)->pContent;

  pCur->row = 0;
  pContent->n = 0;
  QueryContext request;

  for (size_t i = 0; i < pContent->columns.size(); ++i) {
    pContent->data[pContent->columns[i].first].clear();
    request.constraints[pContent->columns[i].first].affinity =
        pContent->columns[i].second;
  }

  for (size_t i = 0; i < argc; ++i) {
    auto expr = (const char *)sqlite3_value_text(argv[i]);
    // Set the expression from SQLite's now-populated argv.
    pContent->constraints[i].second.expr = std::string(expr);
    // Add the constraint to the column-sorted query request map.
    request.constraints[pContent->constraints[i].first].add(
        pContent->constraints[i].second);
  }

  for (auto &row : pContent->generate(request)) {
    for (const auto &column : pContent->columns) {
      pContent->data[column.first].push_back(row[column.first]);
    }
    pContent->n++;
  }

  return SQLITE_OK;
}

template <typename T>
int sqlite3_attach_vtable(sqlite3 *db, const std::string &name) {
  int rc = SQLITE_OK;

  static sqlite3_module module = {
      0,
      xCreate<T>,
      xCreate<T>,
      xBestIndex<T>,
      xDestroy,
      xDestroy,
      xOpen,
      xClose,
      xFilter<T>,
      xNext,
      xEof,
      xColumn<T>,
      xRowid,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
  };

  rc = sqlite3_create_module(db, name.c_str(), &module, 0);
  if (rc == SQLITE_OK) {
    auto format = "CREATE VIRTUAL TABLE temp." + name + " USING " + name;
    rc = sqlite3_exec(db, format.c_str(), 0, 0, 0);
  }
  return rc;
}

void attachVirtualTables(sqlite3 *db);
}
}

DECLARE_REGISTRY(TablePlugins, std::string, osquery::tables::TablePluginRef);
#define REGISTERED_TABLES REGISTRY(TablePlugins)
#define REGISTER_TABLE(name, decorator) REGISTER(TablePlugins, name, decorator);
