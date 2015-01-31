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

#include "osquery/core/virtual_table.h"

namespace osquery {
namespace tables {

int xOpen(sqlite3_vtab *pVTab, sqlite3_vtab_cursor **ppCursor) {
  int rc = SQLITE_NOMEM;
  BaseCursor *pCur;

  pCur = new BaseCursor;

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
  return pCur->row >= pVtab->content->n;
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
  BaseCursor *pCur = (BaseCursor *)cur;
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
    return SQLITE_NOMEM;
  }

  memset(pVtab, 0, sizeof(VirtualTable));
  pVtab->content = new VirtualTableContent;

  PluginResponse response;
  pVtab->content->name = std::string(argv[0]);
  auto status = Registry::call(
      "table", pVtab->content->name, {{"action", "statement"}}, response);
  if (!status.ok() || response.size() == 0) {
    return SQLITE_ERROR;
  }

  int rc = sqlite3_declare_vtab(db, response[0].at("statement").c_str());
  if (rc != SQLITE_OK) {
    return rc;
  }

  // Also set the table column information.
  status = Registry::call(
      "table", pVtab->content->name, {{"action", "columns"}}, response);
  if (!status.ok() || response.size() == 0) {
    return SQLITE_ERROR;
  }

  for (const auto &column : response) {
    pVtab->content->columns.push_back(
        std::make_pair(column.at("name"), column.at("type")));
  }

  *ppVtab = (sqlite3_vtab *)pVtab;
  return rc;
}

int xColumn(sqlite3_vtab_cursor *cur, sqlite3_context *ctx, int col) {
  BaseCursor *pCur = (BaseCursor *)cur;
  auto *pVtab = (VirtualTable *)cur->pVtab;

  if (col >= pVtab->content->columns.size()) {
    return SQLITE_ERROR;
  }

  const auto &column_name = pVtab->content->columns[col].first;
  const auto &type = pVtab->content->columns[col].second;
  if (pCur->row >= pVtab->content->data[column_name].size()) {
    return SQLITE_ERROR;
  }

  const auto &value = pVtab->content->data[column_name][pCur->row];
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

static int xBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo) {
  auto *pVtab = (VirtualTable *)tab;
  pVtab->content->constraints.clear();

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
    pVtab->content->data[pVtab->content->columns[i].first].clear();
    context.constraints[pVtab->content->columns[i].first].affinity =
        pVtab->content->columns[i].second;
  }

  for (size_t i = 0; i < argc; ++i) {
    auto expr = (const char *)sqlite3_value_text(argv[i]);
    // Set the expression from SQLite's now-populated argv.
    pVtab->content->constraints[i].second.expr = std::string(expr);
    // Add the constraint to the column-sorted query request map.
    context.constraints[pVtab->content->constraints[i].first].add(
        pVtab->content->constraints[i].second);
  }

  PluginRequest request;
  PluginResponse response;
  request["action"] = "generate";
  TablePlugin::setRequestFromContext(context, request);
  Registry::call("table", pVtab->content->name, request, response);

  // Now organize the response rows by column instead of row.
  for (const auto &row : response) {
    for (const auto &column : pVtab->content->columns) {
      pVtab->content->data[column.first].push_back(row.at(column.first));
    }
    pVtab->content->n++;
  }

  return SQLITE_OK;
}

int attachTable(sqlite3 *db, const std::string &name) {
  int rc = SQLITE_OK;

  static sqlite3_module module = {
      0,
      xCreate,
      xCreate,
      xBestIndex,
      xDestroy,
      xDestroy,
      xOpen,
      xClose,
      xFilter,
      xNext,
      xEof,
      xColumn,
      xRowid,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
  };

  // Column information is nice for virtual table create call.
  PluginResponse response;
  auto status = Registry::call(
      "table", name, {{"action", "columns_definition"}}, response);
  if (!status.ok() || response.size() == 0) {
    return SQLITE_ERROR;
  }

  rc = sqlite3_create_module(db, name.c_str(), &module, 0);
  if (rc == SQLITE_OK) {
    auto format = "CREATE VIRTUAL TABLE temp." + name + " USING " + name +
                  response[0].at("definition");
    rc = sqlite3_exec(db, format.c_str(), 0, 0, 0);
  }
  return rc;
}

void attachVirtualTables(sqlite3 *db) {
  for (const auto &name : Registry::names("table")) {
    int status = attachTable(db, name);
    if (status != SQLITE_OK) {
      LOG(ERROR) << "Error attaching virtual table: " << name << " (" << status
                 << ")";
    }
  }
}
}
}
