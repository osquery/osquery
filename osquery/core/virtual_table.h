// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <map>

#include <sqlite3.h>
#include <stdio.h>

#include "osquery/tables.h"
#include "osquery/registry.h"

namespace osquery {
namespace tables {

typedef const std::string TableName;
typedef const std::vector<std::string> TableTypes;
typedef const std::vector<std::string> TableColumns;

/// osquery cursor object.
struct base_cursor {
  /// SQLite virtual table cursor.
  sqlite3_vtab_cursor base;
  /// Current cursor position.
  int row;
};

// Our virtual table object
template <class T_STRUCT>
struct x_vtab {
  // virtual table implementations will normally subclass this structure to add
  // additional private and implementation-specific fields
  sqlite3_vtab base;
  // to get custom functionality, add our own struct as well
  T_STRUCT *pContent;
};

struct osquery_table {
  // Table data.
  int n;
  std::map<std::string, std::vector<std::string> > columns;
  ConstraintSet constraints;

  // Helper methods.
  osquery_table() {}
  std::string statement(TableName name, TableTypes types, TableColumns cols);
};

class TablePlugin {
 public:
  virtual int attachVtable(sqlite3 *db) { return -1; }
  virtual ~TablePlugin(){};

 protected:
  TablePlugin(){};
};

typedef std::shared_ptr<TablePlugin> TablePluginRef;

template <class T_VTAB>
int xDestroy(sqlite3_vtab *p) {
  T_VTAB *pVtab = (T_VTAB *)p;
  delete pVtab->pContent;
  delete pVtab;
  return SQLITE_OK;
}

template <class T_CURSOR>
int xOpen(sqlite3_vtab *pVTab, sqlite3_vtab_cursor **ppCursor) {
  int rc = SQLITE_NOMEM;
  T_CURSOR *pCur;

  pCur = new T_CURSOR;

  if (pCur) {
    memset(pCur, 0, sizeof(T_CURSOR));
    *ppCursor = (sqlite3_vtab_cursor *)pCur;
    rc = SQLITE_OK;
  }

  return rc;
}

template <class T_CURSOR>
int xClose(sqlite3_vtab_cursor *cur) {
  T_CURSOR *pCur = (T_CURSOR *)cur;

  delete pCur;
  return SQLITE_OK;
}

template <class T_CURSOR>
int xNext(sqlite3_vtab_cursor *cur) {
  T_CURSOR *pCur = (T_CURSOR *)cur;
  pCur->row++;
  return SQLITE_OK;
}

template <class T_CURSOR, class T_VTAB>
int xEof(sqlite3_vtab_cursor *cur) {
  T_CURSOR *pCur = (T_CURSOR *)cur;
  T_VTAB *pVtab = (T_VTAB *)cur->pVtab;
  return pCur->row >= pVtab->pContent->n;
}

template <class T_CURSOR>
int xRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid) {
  T_CURSOR *pCur = (T_CURSOR *)cur;
  *pRowid = pCur->row;
  return SQLITE_OK;
}

template <class T_VTAB, class T_STRUCT>
int xCreate(sqlite3 *db,
            void *pAux,
            int argc,
            const char *const *argv,
            sqlite3_vtab **ppVtab,
            char **pzErr) {
  int rc = SQLITE_NOMEM;
  T_VTAB *pVtab = new T_VTAB;

  if (pVtab) {
    memset(pVtab, 0, sizeof(T_VTAB));
    pVtab->pContent = new T_STRUCT;

    auto statement = pVtab->pContent->statement(pVtab->pContent->name,
                                                pVtab->pContent->types,
                                                pVtab->pContent->column_names);
    rc = sqlite3_declare_vtab(db, statement.c_str());
  }

  *ppVtab = (sqlite3_vtab *)pVtab;
  return rc;
}

template <typename T>
int xColumn(sqlite3_vtab_cursor *cur, sqlite3_context *ctx, int col) {
  base_cursor *pCur = (base_cursor *)cur;
  T *pVtab = (T *)cur->pVtab;

  if (col >= pVtab->pContent->column_names.size()) {
    return SQLITE_ERROR;
  }

  const auto &column_name = pVtab->pContent->column_names[col];
  const auto &type = pVtab->pContent->types[col];
  if (pCur->row >= pVtab->pContent->columns[column_name].size()) {
    return SQLITE_ERROR;
  }

  const auto &value = pVtab->pContent->columns[column_name][pCur->row];
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
  auto *pContent = ((T *)tab)->pContent;

  int expr_index = 0;
  for (size_t i = 0; i < pIdxInfo->nConstraint; ++i) {
    if (!pIdxInfo->aConstraint[i].usable) {
      // TODO: OR is not usable.
      continue;
    }

    const auto &name = pContent->column_names[pIdxInfo->aConstraint[i].iColumn];
    pContent->constraints.push_back(
        std::make_pair(name, Constraint(pIdxInfo->aConstraint[i].op)));
    pIdxInfo->aConstraintUsage[i].argvIndex = ++expr_index;
  }

  return SQLITE_OK;
}

template <typename T>
static int xFilter(sqlite3_vtab_cursor *pVtabCursor,
                   int idxNum,
                   const char *idxStr,
                   int argc,
                   sqlite3_value **argv) {
  base_cursor *pCur = (base_cursor *)pVtabCursor;
  auto pContent = ((T *)pVtabCursor->pVtab)->pContent;

  pCur->row = 0;
  pContent->n = 0;
  QueryContext request;

  for (size_t i = 0; i < pContent->column_names.size(); ++i) {
    pContent->columns[pContent->column_names[i]].clear();
    request.constraints[pContent->column_names[i]].affinity =
        pContent->types[i];
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
    for (const auto &column_name : pContent->column_names) {
      pContent->columns[column_name].push_back(row[column_name]);
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
      xCreate<x_vtab<T>, T>,
      xCreate<x_vtab<T>, T>,
      xBestIndex<x_vtab<T> >,
      xDestroy<x_vtab<T> >,
      xDestroy<x_vtab<T> >,
      xOpen<base_cursor>,
      xClose<base_cursor>,
      xFilter<x_vtab<T> >,
      xNext<base_cursor>,
      xEof<base_cursor, x_vtab<T> >,
      xColumn<x_vtab<T> >,
      xRowid<base_cursor>,
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
