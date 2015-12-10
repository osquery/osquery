/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/sql/virtual_table.h"

namespace osquery {

SHELL_FLAG(bool, planner, false, "Enable osquery runtime planner output");

namespace tables {
namespace sqlite {

static size_t kPlannerCursorID = 0;

static std::string opString(unsigned char op) {
  switch (op) {
  case EQUALS:
    return "=";
  case GREATER_THAN:
    return ">";
  case LESS_THAN_OR_EQUALS:
    return "<=";
  case LESS_THAN:
    return "<";
  case GREATER_THAN_OR_EQUALS:
    return ">=";
  }
  return "?";
}

static void plan(const std::string &output) {
  if (FLAGS_planner) {
    fprintf(stderr, "osquery planner: %s\n", output.c_str());
  }
}

int xOpen(sqlite3_vtab *tab, sqlite3_vtab_cursor **ppCursor) {
  int rc = SQLITE_NOMEM;
  auto *pCur = new BaseCursor;
  auto *pVtab = (VirtualTable *)tab;
  if (pCur != nullptr) {
    plan("Opening cursor (" + std::to_string(kPlannerCursorID) +
         ") for table: " + pVtab->content->name);
    pCur->id = kPlannerCursorID++;
    pCur->base.pVtab = tab;
    *ppCursor = (sqlite3_vtab_cursor *)pCur;
    rc = SQLITE_OK;
  }

  return rc;
}

int xClose(sqlite3_vtab_cursor *cur) {
  BaseCursor *pCur = (BaseCursor *)cur;
  const auto *pVtab = (VirtualTable *)cur->pVtab;
  plan("Closing cursor (" + std::to_string(pCur->id) + ")");
  if (pVtab != nullptr) {
    // Reset all constraints for the virtual table content.
    if (pVtab->content->constraints.size() > 0) {
      // As each cursor is closed remove the potential constraints it used.
      // Cursors without constraints (full scans) are kept open.
      pVtab->content->constraints.pop_front();
    }
    pVtab->content->constraints_cursor = nullptr;
    pVtab->content->constraints_index = 0;
    pVtab->content->current_term = -1;
  }
  delete pCur;
  return SQLITE_OK;
}

int xEof(sqlite3_vtab_cursor *cur) {
  BaseCursor *pCur = (BaseCursor *)cur;
  if (pCur->row >= pCur->n) {
    // If the requested row exceeds the size of the row set then all rows
    // have been visited, clear the data container.
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
    delete pVtab;
    return SQLITE_NOMEM;
  }

  memset(pVtab, 0, sizeof(VirtualTable));
  pVtab->content = new VirtualTableContent;

  // Create a TablePlugin Registry call, expect column details as the response.
  PluginResponse response;
  pVtab->content->name = std::string(argv[0]);
  // Get the table column information.
  auto status = Registry::call(
      "table", pVtab->content->name, {{"action", "columns"}}, response);
  if (!status.ok() || response.size() == 0) {
    delete pVtab->content;
    delete pVtab;
    return SQLITE_ERROR;
  }

  // Generate an SQL create table statement from the retrieved column details.
  auto statement =
      "CREATE TABLE " + pVtab->content->name + columnDefinition(response);
  int rc = sqlite3_declare_vtab(db, statement.c_str());
  if (rc != SQLITE_OK || !status.ok() || response.size() == 0) {
    delete pVtab->content;
    delete pVtab;
    return (rc != SQLITE_OK) ? rc : SQLITE_ERROR;
  }

  // Keep a local copy of the column details in the VirtualTableContent struct.
  // This allows introspection into the column type without additional calls.
  for (const auto &column : response) {
    pVtab->content->columns.push_back(
        std::make_pair(column.at("name"), columnTypeName(column.at("type"))));
  }
  *ppVtab = (sqlite3_vtab *)pVtab;
  return rc;
}

int xColumn(sqlite3_vtab_cursor *cur, sqlite3_context *ctx, int col) {
  BaseCursor *pCur = (BaseCursor *)cur;
  const auto *pVtab = (VirtualTable *)cur->pVtab;
  if (col >= static_cast<int>(pVtab->content->columns.size())) {
    // Requested column index greater than column set size.
    return SQLITE_ERROR;
  }

  const auto &column_name = pVtab->content->columns[col].first;
  const auto &type = pVtab->content->columns[col].second;
  if (pCur->row >= pCur->data.size()) {
    // Request row index greater than row set size.
    return SQLITE_ERROR;
  }

  // Attempt to cast each xFilter-populated row/column to the SQLite type.
  const auto &value = pCur->data[pCur->row][column_name];
  if (type == TEXT_TYPE) {
    sqlite3_result_text(ctx, value.c_str(), value.size(), SQLITE_STATIC);
  } else if (type == INTEGER_TYPE) {
    long afinite;
    if (!safeStrtol(value, 10, afinite) || afinite < INT_MIN ||
        afinite > INT_MAX) {
      VLOG(1) << "Error casting " << column_name << " (" << value
              << ") to INTEGER";
      afinite = -1;
    }
    sqlite3_result_int(ctx, (int)afinite);
  } else if (type == BIGINT_TYPE || type == UNSIGNED_BIGINT_TYPE) {
    long long afinite;
    if (!safeStrtoll(value, 10, afinite)) {
      VLOG(1) << "Error casting " << column_name << " (" << value
              << ") to BIGINT";
      afinite = -1;
    }
    sqlite3_result_int64(ctx, afinite);
  } else if (type == DOUBLE_TYPE) {
    char *end = nullptr;
    double afinite = strtod(value.c_str(), &end);
    if (end == nullptr || end == value.c_str() || *end != '\0') {
      afinite = 0;
      VLOG(1) << "Error casting " << column_name << " (" << value
              << ") to DOUBLE";
    }
    sqlite3_result_double(ctx, afinite);
  } else {
    LOG(ERROR) << "Error unknown column type " << column_name;
  }

  return SQLITE_OK;
}

static int xBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo) {
  auto *pVtab = (VirtualTable *)tab;
  ConstraintSet constraints;
  // Keep track of the index used for each valid constraint.
  // Expect this index to correspond with argv within xFilter.
  size_t expr_index = 0;
  // If any constraints are unusable increment the cost of the index.
  size_t cost = 0;
  // Expressions operating on the same virtual table are loosely identified by
  // the consecutive sets of terms each of the constraint sets are applied onto.
  // Subsequent attempts from failed (unusable) constraints replace the set,
  // while new sets of terms append.
  int term = -1;
  if (pIdxInfo->nConstraint > 0) {
    for (size_t i = 0; i < static_cast<size_t>(pIdxInfo->nConstraint); ++i) {
      // Record the term index (this index exists across all expressions).
      term = pIdxInfo->aConstraint[i].iTermOffset;
      if (!pIdxInfo->aConstraint[i].usable) {
        // A higher cost less priority, prefer more usable query constraints.
        cost += 10;
        continue;
      }
      // Lookup the column name given an index into the table column set.
      const auto &name =
          pVtab->content->columns[pIdxInfo->aConstraint[i].iColumn].first;
      // Save a pair of the name and the constraint operator.
      // Use this constraint during xFilter by performing a scan and column
      // name lookup through out all cursor constraint lists.
      constraints.push_back(
          std::make_pair(name, Constraint(pIdxInfo->aConstraint[i].op)));
      pIdxInfo->aConstraintUsage[i].argvIndex = ++expr_index;
    }
  }

  // Set the estimated cost based on the number of unusable terms.
  pIdxInfo->estimatedCost = cost;
  if (cost == 0 && term != -1) {
    // This set of constraints is 100% usable.
    // Add the constraint set to the table's tracked constraints.
    pVtab->content->constraints.push_back(constraints);
    pVtab->content->current_term = term;
  } else {
    // Failed.
    if (term != -1 && term != pVtab->content->current_term) {
      pVtab->content->current_term = term;
    }
  }
  return SQLITE_OK;
}

static int xFilter(sqlite3_vtab_cursor *pVtabCursor,
                   int idxNum,
                   const char *idxStr,
                   int argc,
                   sqlite3_value **argv) {
  BaseCursor *pCur = (BaseCursor *)pVtabCursor;
  auto *pVtab = (VirtualTable *)pVtabCursor->pVtab;
  auto *content = pVtab->content;

  pCur->row = 0;
  pCur->n = 0;
  QueryContext context;

  for (size_t i = 0; i < content->columns.size(); ++i) {
    // Set the column affinity for each optional constraint list.
    // There is a separate list for each column name.
    context.constraints[content->columns[i].first].affinity =
        content->columns[i].second;
  }

  // Filtering between cursors happens iteratively, not consecutively.
  // If there are multiple sets of constraints, they apply to each cursor.
  if (content->constraints_cursor == nullptr) {
    content->constraints_cursor = pVtabCursor;
  } else if (content->constraints_cursor != pVtabCursor) {
    content->constraints_index += 1;
    if (content->constraints_index >= content->constraints.size()) {
      content->constraints_index = 0;
    }
    content->constraints_cursor = pVtabCursor;
  }

  // Iterate over every argument to xFilter, filling in constraint values.
  if (content->constraints.size() > 0) {
    auto &constraints = content->constraints[content->constraints_index];
    if (argc > 0) {
      for (size_t i = 0; i < static_cast<size_t>(argc); ++i) {
        auto expr = (const char *)sqlite3_value_text(argv[i]);
        if (expr == nullptr || expr[0] == 0) {
          // SQLite did not expose the expression value.
          continue;
        }
        // Set the expression from SQLite's now-populated argv.
        auto &constraint = constraints[i];
        constraint.second.expr = std::string(expr);
        plan("Adding constraint to cursor (" + std::to_string(pCur->id) +
             "): " + constraint.first + " " + opString(constraint.second.op) +
             " " + constraint.second.expr);
        // Add the constraint to the column-sorted query request map.
        context.constraints[constraint.first].add(constraint.second);
      }
    } else if (constraints.size() > 0) {
      // Constraints failed.
    }
  }
  // Reset the virtual table contents.
  pCur->data.clear();
  // Generate the row data set.
  PluginRequest request = {{"action", "generate"}};
  plan("Scanning rows for cursor (" + std::to_string(pCur->id) + ")");
  TablePlugin::setRequestFromContext(context, request);
  Registry::call("table", pVtab->content->name, request, pCur->data);

  // Set the number of rows.
  pCur->n = pCur->data.size();
  return SQLITE_OK;
}
}
}

Status attachTableInternal(const std::string &name,
                           const std::string &statement,
                           sqlite3 *db) {
  if (SQLiteDBManager::isDisabled(name)) {
    VLOG(1) << "Table " << name << " is disabled, not attaching";
    return Status(0, getStringForSQLiteReturnCode(0));
  }

  // A static module structure does not need specific logic per-table.
  // clang-format off
  static sqlite3_module module = {
      0,
      tables::sqlite::xCreate,
      tables::sqlite::xCreate,
      tables::sqlite::xBestIndex,
      tables::sqlite::xDestroy,
      tables::sqlite::xDestroy,
      tables::sqlite::xOpen,
      tables::sqlite::xClose,
      tables::sqlite::xFilter,
      tables::sqlite::xNext,
      tables::sqlite::xEof,
      tables::sqlite::xColumn,
      tables::sqlite::xRowid,
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
