/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <atomic>

#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/core/process.h"
#include "osquery/sql/virtual_table.h"

namespace osquery {

FLAG(bool, enable_foreign, false, "Enable no-op foreign virtual tables");

FLAG(uint64,
     table_delay,
     0,
     "Add an optional microsecond delay between table scans");

SHELL_FLAG(bool, planner, false, "Enable osquery runtime planner output");

DECLARE_bool(disable_events);

RecursiveMutex kAttachMutex;

namespace tables {
namespace sqlite {

/// For planner and debugging an incrementing cursor ID is used.
static std::atomic<size_t> kPlannerCursorID{0};

/**
 * @brief A next-ID for within-query constraints stacking.
 *
 * As constraints are evaluated within xBestIndex, an IDX is assigned for
 * operator and operand retrieval during xFilter/scanning.
 */
static std::atomic<size_t> kConstraintIndexID{0};

static inline std::string opString(unsigned char op) {
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
  case LIKE:
    return "LIKE";
  case MATCH:
    return "MATCH";
  case GLOB:
    return "GLOB";
  case REGEXP:
    return "REGEX";
  case UNIQUE:
    return "UNIQUE";
  }
  return "?";
}

inline std::string table_doc(const std::string& name) {
  return "https://osquery.io/schema/#" + name;
}

static void plan(const std::string& output) {
  if (FLAGS_planner) {
    fprintf(stderr, "osquery planner: %s\n", output.c_str());
  }
}

int xOpen(sqlite3_vtab* tab, sqlite3_vtab_cursor** ppCursor) {
  int rc = SQLITE_NOMEM;
  auto* pCur = new BaseCursor;
  auto* pVtab = (VirtualTable*)tab;
  if (pCur != nullptr) {
    plan("Opening cursor (" + std::to_string(kPlannerCursorID) +
         ") for table: " + pVtab->content->name);
    pCur->id = kPlannerCursorID++;
    pCur->base.pVtab = tab;
    *ppCursor = (sqlite3_vtab_cursor*)pCur;
    rc = SQLITE_OK;
  }

  return rc;
}

int xClose(sqlite3_vtab_cursor* cur) {
  BaseCursor* pCur = (BaseCursor*)cur;
  plan("Closing cursor (" + std::to_string(pCur->id) + ")");
  delete pCur;
  return SQLITE_OK;
}

int xEof(sqlite3_vtab_cursor* cur) {
  BaseCursor* pCur = (BaseCursor*)cur;
  if (pCur->uses_generator) {
    if (*pCur->generator) {
      return false;
    }
    pCur->generator = nullptr;
    return true;
  }

  if (pCur->row >= pCur->n) {
    // If the requested row exceeds the size of the row set then all rows
    // have been visited, clear the data container.
    return true;
  }
  return false;
}

int xDestroy(sqlite3_vtab* p) {
  auto* pVtab = (VirtualTable*)p;
  delete pVtab->content;
  delete pVtab;
  return SQLITE_OK;
}

int xNext(sqlite3_vtab_cursor* cur) {
  BaseCursor* pCur = (BaseCursor*)cur;
  if (pCur->uses_generator) {
    pCur->generator->operator()();
    if (*pCur->generator) {
      pCur->current = pCur->generator->get();
    }
  }
  pCur->row++;
  return SQLITE_OK;
}

int xRowid(sqlite3_vtab_cursor* cur, sqlite_int64* pRowid) {
  const BaseCursor* pCur = (BaseCursor*)cur;
  *pRowid = pCur->row;
  return SQLITE_OK;
}

int xCreate(sqlite3* db,
            void* pAux,
            int argc,
            const char* const* argv,
            sqlite3_vtab** ppVtab,
            char** pzErr) {
  auto* pVtab = new VirtualTable;
  if (!pVtab || argc == 0 || argv[0] == nullptr) {
    delete pVtab;
    return SQLITE_NOMEM;
  }

  memset(pVtab, 0, sizeof(VirtualTable));
  pVtab->content = new VirtualTableContent;
  pVtab->instance = (SQLiteDBInstance*)pAux;

  // Create a TablePlugin Registry call, expect column details as the response.
  PluginResponse response;
  pVtab->content->name = std::string(argv[0]);
  const auto& name = pVtab->content->name;
  // Get the table column information.
  auto status =
      Registry::call("table", name, {{"action", "columns"}}, response);
  if (!status.ok() || response.size() == 0) {
    delete pVtab->content;
    delete pVtab;
    return SQLITE_ERROR;
  }

  // Generate an SQL create table statement from the retrieved column details.
  // This call to columnDefinition requests column aliases (as HIDDEN columns).
  auto statement = "CREATE TABLE " + name + columnDefinition(response, true);
  int rc = sqlite3_declare_vtab(db, statement.c_str());
  if (rc != SQLITE_OK || !status.ok() || response.size() == 0) {
    LOG(ERROR) << "Error creating virtual table: " << name << " (" << rc
               << "): " << getStringForSQLiteReturnCode(rc);
    VLOG(1) << "Cannot create virtual table using: " << statement;
    delete pVtab->content;
    delete pVtab;
    return (rc != SQLITE_OK) ? rc : SQLITE_ERROR;
  }

  // Tables may request aliases as views.
  std::set<std::string> views;

  // Keep a local copy of the column details in the VirtualTableContent struct.
  // This allows introspection into the column type without additional calls.
  for (const auto& column : response) {
    if (column.count("id") == 0) {
      // This does not define a column type.
      continue;
    }

    if (column.at("id") == "column" && column.count("name") &&
        column.count("type")) {
      // This is a malformed column definition.
      // Populate the virtual table specific persistent column information.
      pVtab->content->columns.push_back(std::make_tuple(
          column.at("name"),
          columnTypeName(column.at("type")),
          (ColumnOptions)AS_LITERAL(INTEGER_LITERAL, column.at("op"))));
    } else if (column.at("id") == "alias" && column.count("alias")) {
      // Create associated views for table aliases.
      views.insert(column.at("alias"));
    } else if (column.at("id") == "columnAlias" && column.count("name") &&
               column.count("target")) {
      // Record the column in the set of columns.
      // This is required because SQLITE uses indexes to identify columns.
      // Use an UNKNOWN_TYPE as a pseudo-mask, since the type does not matter.
      pVtab->content->columns.push_back(std::make_tuple(
          column.at("name"), UNKNOWN_TYPE, ColumnOptions::HIDDEN));
      // Record a mapping of the requested column alias name.
      size_t target_index = 0;
      for (size_t i = 0; i < pVtab->content->columns.size(); i++) {
        const auto& target_column = pVtab->content->columns[i];
        if (std::get<0>(target_column) == column.at("target")) {
          target_index = i;
          break;
        }
      }
      pVtab->content->aliases[column.at("name")] = target_index;
    } else if (column.at("id") == "attributes") {
      // Store the attributes locally so they may be passed to the SQL object.
      pVtab->content->attributes =
          (TableAttributes)AS_LITERAL(INTEGER_LITERAL, column.at("attributes"));
    }
  }

  // Create the requested 'aliases'.
  for (const auto& view : views) {
    statement = "CREATE VIEW " + view + " AS SELECT * FROM " + name;
    sqlite3_exec(db, statement.c_str(), nullptr, nullptr, nullptr);
  }
  *ppVtab = (sqlite3_vtab*)pVtab;
  return rc;
}

int xColumn(sqlite3_vtab_cursor* cur, sqlite3_context* ctx, int col) {
  BaseCursor* pCur = (BaseCursor*)cur;
  const auto* pVtab = (VirtualTable*)cur->pVtab;
  if (col >= static_cast<int>(pVtab->content->columns.size())) {
    // Requested column index greater than column set size.
    return SQLITE_ERROR;
  }
  if (!pCur->uses_generator && pCur->row >= pCur->data.size()) {
    // Request row index greater than row set size.
    return SQLITE_ERROR;
  }

  auto& column_name = std::get<0>(pVtab->content->columns[col]);
  auto& type = std::get<1>(pVtab->content->columns[col]);
  if (pVtab->content->aliases.count(column_name)) {
    // Overwrite the aliased column with the type and name of the new column.
    type = std::get<1>(
        pVtab->content->columns[pVtab->content->aliases.at(column_name)]);
    column_name = std::get<0>(
        pVtab->content->columns[pVtab->content->aliases.at(column_name)]);
  }

  Row* row = nullptr;
  if (pCur->uses_generator) {
    row = &pCur->current;
  } else {
    row = &pCur->data[pCur->row];
  }

  // Attempt to cast each xFilter-populated row/column to the SQLite type.
  const auto& value = (*row)[column_name];
  if (row->count(column_name) == 0) {
    // Missing content.
    VLOG(1) << "Error " << column_name << " is empty";
    sqlite3_result_null(ctx);
  } else if (type == TEXT_TYPE) {
    sqlite3_result_text(
        ctx, value.c_str(), static_cast<int>(value.size()), SQLITE_STATIC);
  } else if (type == INTEGER_TYPE) {
    long afinite;
    if (!safeStrtol(value, 0, afinite) || afinite < INT_MIN ||
        afinite > INT_MAX) {
      VLOG(1) << "Error casting " << column_name << " (" << value
              << ") to INTEGER";
      sqlite3_result_null(ctx);
    } else {
      sqlite3_result_int(ctx, (int)afinite);
    }
  } else if (type == BIGINT_TYPE || type == UNSIGNED_BIGINT_TYPE) {
    long long afinite;
    if (!safeStrtoll(value, 0, afinite)) {
      VLOG(1) << "Error casting " << column_name << " (" << value
              << ") to BIGINT";
      sqlite3_result_null(ctx);
    } else {
      sqlite3_result_int64(ctx, afinite);
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

static inline bool sensibleComparison(ColumnType type, unsigned char op) {
  if (type == TEXT_TYPE) {
    if (op == GREATER_THAN || op == GREATER_THAN_OR_EQUALS || op == LESS_THAN ||
        op == LESS_THAN_OR_EQUALS) {
      return false;
    }
  }
  return true;
}

static int xBestIndex(sqlite3_vtab* tab, sqlite3_index_info* pIdxInfo) {
  auto* pVtab = (VirtualTable*)tab;
  const auto& columns = pVtab->content->columns;

  ConstraintSet constraints;
  // Keep track of the index used for each valid constraint.
  // Expect this index to correspond with argv within xFilter.
  size_t expr_index = 0;
  // If any constraints are unusable increment the cost of the index.
  double cost = 1;

  // Tables may have requirements or use indexes.
  bool required_satisfied = false;
  bool index_used = false;

  // Expressions operating on the same virtual table are loosely identified by
  // the consecutive sets of terms each of the constraint sets are applied onto.
  // Subsequent attempts from failed (unusable) constraints replace the set,
  // while new sets of terms append.
  if (pIdxInfo->nConstraint > 0) {
    for (size_t i = 0; i < static_cast<size_t>(pIdxInfo->nConstraint); ++i) {
      // Record the term index (this index exists across all expressions).
      const auto& constraint_info = pIdxInfo->aConstraint[i];
#if defined(DEBUG)
      plan("Evaluating constraints for table: " + pVtab->content->name +
           " [index=" + std::to_string(i) + " column=" +
           std::to_string(constraint_info.iColumn) + " term=" +
           std::to_string((int)constraint_info.iTermOffset) + " usable=" +
           std::to_string((int)constraint_info.usable) + "]");
#endif
      if (!constraint_info.usable) {
        // A higher cost less priority, prefer more usable query constraints.
        cost += 10;
        continue;
      }

      // Lookup the column name given an index into the table column set.
      if (constraint_info.iColumn < 0 ||
          static_cast<size_t>(constraint_info.iColumn) >=
              pVtab->content->columns.size()) {
        cost += 10;
        continue;
      }
      const auto& name = std::get<0>(columns[constraint_info.iColumn]);
      const auto& type = std::get<1>(columns[constraint_info.iColumn]);
      if (!sensibleComparison(type, constraint_info.op)) {
        cost += 10;
        continue;
      }

      // Check if this constraint is on an index or required column.
      const auto& options = std::get<2>(columns[constraint_info.iColumn]);
      if (options & ColumnOptions::REQUIRED) {
        index_used = true;
        required_satisfied = true;
      } else if (options & (ColumnOptions::INDEX | ColumnOptions::ADDITIONAL)) {
        index_used = true;
      }

      // Save a pair of the name and the constraint operator.
      // Use this constraint during xFilter by performing a scan and column
      // name lookup through out all cursor constraint lists.
      constraints.push_back(
          std::make_pair(name, Constraint(constraint_info.op)));
      pIdxInfo->aConstraintUsage[i].argvIndex = static_cast<int>(++expr_index);
#if defined(DEBUG)
      plan("Adding constraint for table: " + pVtab->content->name +
           " [column=" + name + " arg_index=" + std::to_string(expr_index) +
           " op=" + std::to_string(constraint_info.op) + "]");
#endif
    }
  }

  // Check the table for a required column.
  for (const auto& column : columns) {
    auto& options = std::get<2>(column);
    if (options & ColumnOptions::REQUIRED && !required_satisfied) {
      // A column is marked required, but no constraint satisfies.
      cost += 1e10;
      break;
    }
  }

  if (!index_used) {
    // A column is marked index, but no index constraint was provided.
    cost += 200;
  }

  pIdxInfo->idxNum = static_cast<int>(kConstraintIndexID++);
#if defined(DEBUG)
  plan("Recording constraint set for table: " + pVtab->content->name +
       " [cost=" + std::to_string(cost) + " size=" +
       std::to_string(constraints.size()) + " idx=" +
       std::to_string(pIdxInfo->idxNum) + "]");
#endif
  // Add the constraint set to the table's tracked constraints.
  pVtab->content->constraints[pIdxInfo->idxNum] = std::move(constraints);
  pIdxInfo->estimatedCost = cost;
  return SQLITE_OK;
}

static int xFilter(sqlite3_vtab_cursor* pVtabCursor,
                   int idxNum,
                   const char* idxStr,
                   int argc,
                   sqlite3_value** argv) {
  BaseCursor* pCur = (BaseCursor*)pVtabCursor;
  auto* pVtab = (VirtualTable*)pVtabCursor->pVtab;
  auto* content = pVtab->content;
  if (FLAGS_table_delay > 0 && pVtab->instance->tableCalled(content)) {
    // Apply an optional sleep between table calls.
    sleepFor(FLAGS_table_delay);
  }
  pVtab->instance->addAffectedTable(content);

  pCur->row = 0;
  pCur->n = 0;
  QueryContext context(content);

  // The SQLite instance communicates to the TablePlugin via the context.
  context.useCache(pVtab->instance->useCache());

  // Track required columns, this is different than the requirements check
  // that occurs within BestIndex because this scan includes a cursor.
  // For each cursor used, if a requirement exists, we need to scan the
  // selected set of constraints for a match.
  bool required_satisfied = true;

  // The specialized table attribute USER_BASED imposes a special requirement
  // for UID. This may be represented in the requirements, but otherwise
  // would benefit from specific notification to the caller.
  bool user_based_satisfied = !(
      (content->attributes & TableAttributes::USER_BASED) > 0 && isUserAdmin());

  // For event-based tables, help the caller if events are disabled.
  bool events_satisfied =
      ((content->attributes & TableAttributes::EVENT_BASED) == 0 ||
       !FLAGS_disable_events);

  std::map<std::string, ColumnOptions> options;
  for (size_t i = 0; i < content->columns.size(); ++i) {
    // Set the column affinity for each optional constraint list.
    // There is a separate list for each column name.
    auto column_name = std::get<0>(content->columns[i]);
    context.constraints[column_name].affinity =
        std::get<1>(content->columns[i]);
    // Save the column options for comparison within constraints enumeration.
    options[column_name] = std::get<2>(content->columns[i]);
    if (options[column_name] & ColumnOptions::REQUIRED) {
      required_satisfied = false;
    }
  }

// Filtering between cursors happens iteratively, not consecutively.
// If there are multiple sets of constraints, they apply to each cursor.
#if defined(DEBUG)
  plan("Filtering called for table: " + content->name + " [constraint_count=" +
       std::to_string(content->constraints.size()) + " argc=" +
       std::to_string(argc) + " idx=" + std::to_string(idxNum) + "]");
#endif

  // Iterate over every argument to xFilter, filling in constraint values.
  if (content->constraints.size() > 0) {
    auto& constraints = content->constraints[idxNum];
    if (argc > 0) {
      for (size_t i = 0; i < static_cast<size_t>(argc); ++i) {
        auto expr = (const char*)sqlite3_value_text(argv[i]);
        if (expr == nullptr || expr[0] == 0) {
          // SQLite did not expose the expression value.
          continue;
        }
        // Set the expression from SQLite's now-populated argv.
        auto& constraint = constraints[i];
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

    // Evaluate index and optimized constraint requirements.
    // These are satisfied regardless of expression content availability.
    for (const auto& constraint : constraints) {
      if (options[constraint.first] & ColumnOptions::REQUIRED) {
        // A required option exists in the constraints.
        required_satisfied = true;
      }

      if (!user_based_satisfied &&
          (constraint.first == "uid" || constraint.first == "username")) {
        // UID was required and exists in the constraints.
        user_based_satisfied = true;
      }
    }
  }

  if (!user_based_satisfied) {
    LOG(WARNING) << "The " << pVtab->content->name
                 << " table returns data based on the current user by default, "
                    "consider JOINing against the users table";
  } else if (!required_satisfied) {
    LOG(WARNING)
        << "Table " << pVtab->content->name
        << " was queried without a required column in the WHERE clause";
  } else if (!events_satisfied) {
    LOG(WARNING) << "Table " << pVtab->content->name
                 << " is event-based but events are disabled";
  }

  // Provide a helpful reference to table documentation within the shell.
  if (Initializer::isShell() &&
      (!user_based_satisfied || !required_satisfied || !events_satisfied)) {
    LOG(WARNING) << "Please see the table documentation: "
                 << table_doc(pVtab->content->name);
  }

  // Reset the virtual table contents.
  pCur->data.clear();
  options.clear();

  // Generate the row data set.
  plan("Scanning rows for cursor (" + std::to_string(pCur->id) + ")");
  if (Registry::get().exists("table", pVtab->content->name, true)) {
    auto plugin = Registry::get().plugin("table", pVtab->content->name);
    auto table = std::dynamic_pointer_cast<TablePlugin>(plugin);
    if (table->usesGenerator()) {
      pCur->uses_generator = true;
      pCur->generator = std::make_unique<RowGenerator::pull_type>(
          std::bind(&TablePlugin::generator,
                    table,
                    std::placeholders::_1,
                    std::move(context)));
      if (*pCur->generator) {
        pCur->current = pCur->generator->get();
      }
      return SQLITE_OK;
    }
    pCur->data = table->generate(context);
  } else {
    PluginRequest request = {{"action", "generate"}};
    TablePlugin::setRequestFromContext(context, request);
    Registry::call("table", pVtab->content->name, request, pCur->data);
  }

  // Set the number of rows.
  pCur->n = pCur->data.size();
  return SQLITE_OK;
}
}
}

Status attachTableInternal(const std::string& name,
                           const std::string& statement,
                           const SQLiteDBInstanceRef& instance) {
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
      nullptr, /* Update */
      nullptr, /* Begin */
      nullptr, /* Sync */
      nullptr, /* Commit */
      nullptr, /* Rollback */
      nullptr, /* FindFunction */
      nullptr, /* Rename */
      nullptr, /* Savepoint */
      nullptr, /* Release */
      nullptr, /* RollbackTo */
  };
  // clang-format on

  // Note, if the clientData API is used then this will save a registry call
  // within xCreate.
  auto lock(instance->attachLock());

  int rc = sqlite3_create_module(
      instance->db(), name.c_str(), &module, (void*)&(*instance));
  if (rc == SQLITE_OK || rc == SQLITE_MISUSE) {
    auto format =
        "CREATE VIRTUAL TABLE temp." + name + " USING " + name + statement;
    rc = sqlite3_exec(instance->db(), format.c_str(), nullptr, nullptr, 0);
  } else {
    LOG(ERROR) << "Error attaching table: " << name << " (" << rc << ")";
  }
  return Status(rc, getStringForSQLiteReturnCode(rc));
}

Status detachTableInternal(const std::string& name,
                           const SQLiteDBInstanceRef& instance) {
  auto lock(instance->attachLock());
  auto format = "DROP TABLE IF EXISTS temp." + name;
  int rc = sqlite3_exec(instance->db(), format.c_str(), nullptr, nullptr, 0);
  if (rc != SQLITE_OK) {
    LOG(ERROR) << "Error detaching table: " << name << " (" << rc << ")";
  }

  return Status(rc, getStringForSQLiteReturnCode(rc));
}

Status attachFunctionInternal(
    const std::string& name,
    std::function<
        void(sqlite3_context* context, int argc, sqlite3_value** argv)> func) {
  // Hold the manager connection instance again in callbacks.
  auto dbc = SQLiteDBManager::get();
  // Add some shell-specific functions to the instance.
  auto lock(dbc->attachLock());
  int rc = sqlite3_create_function(
      dbc->db(),
      name.c_str(),
      0,
      SQLITE_UTF8,
      nullptr,
      *func.target<void (*)(sqlite3_context*, int, sqlite3_value**)>(),
      nullptr,
      nullptr);
  return Status(rc);
}

void attachVirtualTables(const SQLiteDBInstanceRef& instance) {
  if (FLAGS_enable_foreign) {
#if !defined(OSQUERY_EXTERNAL)
    // Foreign table schema is available for the shell and daemon only.
    registerForeignTables();
#endif
  }

  PluginResponse response;
  for (const auto& name : RegistryFactory::get().names("table")) {
    // Column information is nice for virtual table create call.
    auto status =
        Registry::call("table", name, {{"action", "columns"}}, response);
    if (status.ok()) {
      auto statement = columnDefinition(response, true);
      attachTableInternal(name, statement, instance);
    }
  }
}
}
