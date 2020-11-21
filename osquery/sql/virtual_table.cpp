/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <atomic>
#include <unordered_set>

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/virtual_table.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {

FLAG(bool, enable_foreign, false, "Enable no-op foreign virtual tables");

FLAG(uint64,
     table_delay,
     0,
     "Add an optional microsecond delay between table scans");

FLAG(bool,
     extensions_default_index,
     true,
     "Enable INDEX on all extension table columns (default true)");

FLAG(bool, table_exceptions, false, "Allow tables to throw exceptions");

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

/// We consider the max-cost as an error-state, e.g., unusable constraints.
const double kMaxIndexCost{1000000};

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

namespace {
/// A list of tables that come from extensions; it is used to determine which
/// table can be read/write
class TableList final {
  std::unordered_set<std::string> table_list;
  mutable Mutex mutex;

 public:
  void insert(const std::string& table) {
    WriteLock write_lock(mutex);
    table_list.insert(table);
  }

  bool contains(const std::string& table_name) const {
    ReadLock lock(mutex);

    return (std::find(table_list.begin(), table_list.end(), table_name) !=
            table_list.end());
  }
};

TableList extension_table_list;

// A map containing an sqlite module object for each virtual table
std::unordered_map<std::string, struct sqlite3_module> sqlite_module_map;
Mutex sqlite_module_map_mutex;

bool getColumnValue(std::string& value,
                    size_t index,
                    size_t argc,
                    sqlite3_value** argv) {
  value.clear();

  if (index >= argc) {
    return false;
  }

  auto sqlite_value = argv[index];
  switch (sqlite3_value_type(sqlite_value)) {
  case SQLITE_INTEGER: {
    auto temp = sqlite3_value_int64(sqlite_value);
    value = std::to_string(temp);
    break;
  }

  case SQLITE_FLOAT: {
    auto temp = sqlite3_value_double(sqlite_value);
    value = std::to_string(temp);
    break;
  }

  case SQLITE_BLOB:
  case SQLITE3_TEXT: {
    auto data_ptr = static_cast<const char*>(sqlite3_value_blob(sqlite_value));
    auto buffer_size = static_cast<size_t>(sqlite3_value_bytes(sqlite_value));

    value.assign(data_ptr, buffer_size);
    break;
  }

  case SQLITE_NULL: {
    break;
  }

  default: {
    LOG(ERROR) << "Invalid column type returned by sqlite";
    return false;
  }
  }

  return true;
}

// Type-aware serializer to pass parameters between osquery and the extension
int serializeUpdateParameters(std::string& json_value_array,
                              size_t argc,
                              sqlite3_value** argv,
                              const TableColumns& columnDescriptors) {
  if (columnDescriptors.size() != argc - 2U) {
    VLOG(1) << "Wrong column count: " << argc - 2U
            << ". Expected: " << columnDescriptors.size();
    return SQLITE_RANGE;
  }

  auto document = rapidjson::Document();
  document.SetArray();

  auto& allocator = document.GetAllocator();

  for (size_t i = 2U; i < argc; i++) {
    auto sqlite_value = argv[i];

    const auto& columnDescriptor = columnDescriptors[i - 2U];
    const auto& columnType = std::get<1>(columnDescriptor);

    const auto& columnOptions = std::get<2>(columnDescriptor);
    bool requiredColumn = (columnOptions == ColumnOptions::INDEX ||
                           columnOptions == ColumnOptions::REQUIRED);

    auto receivedValueType = sqlite3_value_type(sqlite_value);
    switch (receivedValueType) {
    case SQLITE_INTEGER: {
      if (columnType != INTEGER_TYPE && columnType != BIGINT_TYPE &&
          columnType != UNSIGNED_BIGINT_TYPE) {
        return SQLITE_MISMATCH;
      }

      auto integer =
          static_cast<std::int64_t>(sqlite3_value_int64(sqlite_value));

      document.PushBack(integer, allocator);
      break;
    }

    case SQLITE_FLOAT: {
      if (columnType != DOUBLE_TYPE) {
        return SQLITE_MISMATCH;
      }

      document.PushBack(sqlite3_value_double(sqlite_value), allocator);
      break;
    }

    case SQLITE_BLOB:
    case SQLITE3_TEXT: {
      bool typeMismatch = false;
      if (receivedValueType == SQLITE_BLOB) {
        typeMismatch = columnType != BLOB_TYPE;
      } else {
        typeMismatch = columnType != TEXT_TYPE;
      }

      if (typeMismatch) {
        return SQLITE_MISMATCH;
      }

      auto data_pointer = sqlite3_value_blob(sqlite_value);
      auto buffer_size = sqlite3_value_bytes(sqlite_value);

      std::string string_data;
      string_data.resize(buffer_size);
      std::memcpy(&string_data[0], data_pointer, buffer_size);

      rapidjson::Value value(string_data, allocator);
      document.PushBack(value, allocator);

      break;
    }

    case SQLITE_NULL: {
      if (requiredColumn) {
        return SQLITE_MISMATCH;
      }

      rapidjson::Value value;
      value.SetNull();

      document.PushBack(value, allocator);
      break;
    }

    default: {
      LOG(ERROR) << "Invalid column type returned by sqlite";
      return SQLITE_MISMATCH;
    }
    }
  }

  rapidjson::StringBuffer buffer;
  buffer.Clear();

  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  document.Accept(writer);

  json_value_array = buffer.GetString();
  return SQLITE_OK;
}

void setTableErrorMessage(sqlite3_vtab* vtable,
                          const std::string& error_message) {
  // We are required to always replace the pointer with memory
  // allocated with sqlite3_malloc. This buffer is freed automatically
  // by sqlite3 on exit
  //
  // Documentation: https://www.sqlite.org/vtab.html section 1.2

  if (vtable->zErrMsg != nullptr) {
    sqlite3_free(vtable->zErrMsg);
  }

  auto buffer_size = static_cast<int>(error_message.size() + 1);

  vtable->zErrMsg = static_cast<char*>(sqlite3_malloc(buffer_size));
  if (vtable->zErrMsg != nullptr) {
    memcpy(vtable->zErrMsg, error_message.c_str(), buffer_size);
  }
}
} // namespace

inline std::string table_doc(const std::string& name) {
  return "https://osquery.io/schema/#" + name;
}

static void plan(const std::string& output) {
  if (FLAGS_planner) {
    fprintf(stderr, "osquery planner: %s\n", output.c_str());
  }
}

int xOpen(sqlite3_vtab* tab, sqlite3_vtab_cursor** ppCursor) {
  auto* pCur = new BaseCursor;
  auto* pVtab = (VirtualTable*)tab;
  if (FLAGS_planner) {
    plan("xOpen Opening cursor (" + std::to_string(kPlannerCursorID) +
         ") for table: " + pVtab->content->name);
  }
  pCur->id = kPlannerCursorID++;
  pCur->base.pVtab = tab;
  *ppCursor = (sqlite3_vtab_cursor*)pCur;

  return SQLITE_OK;
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
  *pRowid = 0;

  const BaseCursor* pCur = (BaseCursor*)cur;
  auto data_it = std::next(pCur->rows.begin(), pCur->row);
  if (data_it >= pCur->rows.end()) {
    return SQLITE_ERROR;
  }

  // Use the rowid returned by the extension, if available; most likely, this
  // will only be used by extensions providing read/write tables
  const auto& current_row = *data_it;
  return current_row->get_rowid(pCur->row, pRowid);
}

int xUpdate(sqlite3_vtab* p,
            int argc,
            sqlite3_value** argv,
            sqlite3_int64* pRowid) {
  auto argument_count = static_cast<size_t>(argc);
  auto* pVtab = (VirtualTable*)p;

  auto content = pVtab->content;
  const auto& columnDescriptors = content->columns;

  std::string table_name = pVtab->content->name;

  // The SQLite instance communicates to the TablePlugin via the context.
  QueryContext context(content);
  PluginRequest plugin_request;

  if (argument_count == 1U) {
    // This is a simple delete operation
    plugin_request = {{"action", "delete"}};

    auto row_to_delete = sqlite3_value_int64(argv[0]);
    plugin_request.insert({"id", std::to_string(row_to_delete)});

  } else if (sqlite3_value_type(argv[0]) == SQLITE_NULL) {
    // This is an INSERT query; if the rowid has been generated for us, we'll
    // find it inside argv[1]
    plugin_request = {{"action", "insert"}};

    // Add the values to insert; we should have a value for each column present
    // in the table, even if the user did not specify a value (in which case
    // we will find a nullptr)
    std::string json_value_array;
    auto serializerError = serializeUpdateParameters(
        json_value_array, argument_count, argv, columnDescriptors);
    if (serializerError != SQLITE_OK) {
      VLOG(1) << "Failed to serialize the INSERT request";
      return serializerError;
    }

    plugin_request.insert({"json_value_array", json_value_array});

    if (sqlite3_value_type(argv[1]) != SQLITE_NULL) {
      plugin_request.insert({"auto_rowid", "true"});

      std::string auto_generated_rowid;
      if (!getColumnValue(auto_generated_rowid, 1U, argument_count, argv)) {
        VLOG(1) << "Failed to retrieve the column value";
        return SQLITE_ERROR;
      }

      plugin_request.insert({"id", auto_generated_rowid});

    } else {
      plugin_request.insert({"auto_rowid", "false"});
    }

  } else if (sqlite3_value_type(argv[0]) == SQLITE_INTEGER) {
    // This is an UPDATE query; we have to update the rowid value in some
    // cases (if argv[1] is populated)
    plugin_request = {{"action", "update"}};

    std::string current_rowid;
    if (!getColumnValue(current_rowid, 0U, argument_count, argv)) {
      VLOG(1) << "Failed to retrieve the column value";
      return SQLITE_ERROR;
    }

    plugin_request.insert({"id", current_rowid});

    // Get the new rowid, if any
    if (sqlite3_value_type(argv[1]) == SQLITE_INTEGER) {
      std::string new_rowid;
      if (!getColumnValue(new_rowid, 1U, argument_count, argv)) {
        VLOG(1) << "Failed to retrieve the column value";
        return SQLITE_ERROR;
      }

      if (new_rowid != plugin_request.at("id")) {
        plugin_request.insert({"new_id", new_rowid});
      }
    }

    // Get the values to update
    std::string json_value_array;
    auto serializerError = serializeUpdateParameters(
        json_value_array, argument_count, argv, columnDescriptors);
    if (serializerError != SQLITE_OK) {
      VLOG(1) << "Failed to serialize the UPDATE request";
      return serializerError;
    }

    plugin_request.insert({"json_value_array", json_value_array});

  } else {
    VLOG(1) << "Invalid xUpdate call";
    return SQLITE_ERROR;
  }

  TablePlugin::setRequestFromContext(context, plugin_request);

  // Forward the query to the table extension
  PluginResponse response_list;
  Registry::call("table", table_name, plugin_request, response_list);

  // Validate the response
  if (response_list.size() != 1) {
    VLOG(1) << "Invalid response from the extension table";
    return SQLITE_ERROR;
  }

  const auto& response = response_list.at(0);
  if (response.count("status") == 0) {
    VLOG(1) << "Invalid response from the extension table; the status field is "
               "missing";

    return SQLITE_ERROR;
  }

  const auto& status_value = response.at("status");
  if (status_value == "readonly") {
    auto error_message =
        "table " + pVtab->content->name + " may not be modified";

    setTableErrorMessage(p, error_message);
    return SQLITE_READONLY;

  } else if (status_value == "failure") {
    auto custom_error_message_it = response.find("message");
    if (custom_error_message_it == response.end()) {
      return SQLITE_ERROR;
    }

    const auto& custom_error_message = custom_error_message_it->second;
    setTableErrorMessage(p, custom_error_message);
    return SQLITE_ERROR;

  } else if (status_value == "constraint") {
    return SQLITE_CONSTRAINT;

  } else if (status_value != "success") {
    VLOG(1) << "Invalid response from the extension table; the status field "
               "could not be recognized";

    return SQLITE_ERROR;
  }

  // INSERT actions must always return a valid rowid to sqlite
  if (plugin_request.at("action") == "insert") {
    std::string rowid;

    if (plugin_request.at("auto_rowid") == "true") {
      if (!getColumnValue(rowid, 1U, argument_count, argv)) {
        VLOG(1) << "Failed to retrieve the rowid value";
        return SQLITE_ERROR;
      }

    } else {
      auto id_it = response.find("id");
      if (id_it == response.end()) {
        VLOG(1) << "The plugin did not return a row id";
        return SQLITE_ERROR;
      }

      rowid = id_it->second;
    }

    auto exp = tryTo<long long>(rowid);
    if (exp.isError()) {
      VLOG(1) << "The plugin did not return a valid row id";
      return SQLITE_ERROR;
    }
    *pRowid = exp.take();
  }

  return SQLITE_OK;
}

int xCreate(sqlite3* db,
            void* pAux,
            int argc,
            const char* const* argv,
            sqlite3_vtab** ppVtab,
            char** pzErr) {
  if (argc == 0 || argv[0] == nullptr) {
    return SQLITE_NOMEM;
  }

  auto* pVtab = new VirtualTable;
  pVtab->base = {};
  pVtab->content = std::make_shared<VirtualTableContent>();
  pVtab->instance = (SQLiteDBInstance*)pAux;

  // Create a TablePlugin Registry call, expect column details as the response.
  PluginResponse response;
  pVtab->content->name = std::string(argv[0]);
  const auto& name = pVtab->content->name;

  // Get the table column information.
  auto status =
      Registry::call("table", name, {{"action", "columns"}}, response);
  if (!status.ok() || response.size() == 0) {
    delete pVtab;
    return SQLITE_ERROR;
  }

  // Tables implemented from extensions can be made read/write if they implement
  // the correct methods
  bool is_extension = extension_table_list.contains(name);

  // Generate an SQL create table statement from the retrieved column details.
  // This call to columnDefinition requests column aliases (as HIDDEN columns).
  auto statement =
      "CREATE TABLE " + name + columnDefinition(response, true, is_extension);

  int rc = sqlite3_declare_vtab(db, statement.c_str());
  if (rc != SQLITE_OK || !status.ok() || response.size() == 0) {
    LOG(ERROR) << "Error creating virtual table: " << name << " (" << rc
               << "): " << getStringForSQLiteReturnCode(rc);

    VLOG(1) << "Cannot create virtual table using: " << statement;
    delete pVtab;
    return (rc != SQLITE_OK) ? rc : SQLITE_ERROR;
  }

  // Tables may request aliases as views.
  std::set<std::string> views;

  // Keep a local copy of the column details in the VirtualTableContent struct.
  // This allows introspection into the column type without additional calls.
  for (const auto& column : response) {
    auto cid = column.find("id");
    if (cid == column.end()) {
      // This does not define a column type.
      continue;
    }

    auto cname = column.find("name");
    auto ctype = column.find("type");
    if (cid->second == "column" && cname != column.end() &&
        ctype != column.end()) {
      // This is a malformed column definition.
      // Populate the virtual table specific persistent column information.
      auto options = ColumnOptions::DEFAULT;
      auto cop = column.find("op");
      if (cop != column.end()) {
        auto op = tryTo<long>(cop->second);
        if (op) {
          options = static_cast<ColumnOptions>(op.take());
        }
      }

      if (is_extension && FLAGS_extensions_default_index) {
        if (ColumnOptions::DEFAULT == options) {
          options = ColumnOptions::INDEX;
        } else {
          // The extension is effected by extensions_default_index.
          // Consider adding a deprecation warning (#6035).
        }
      }

      pVtab->content->columns.push_back(std::make_tuple(
          cname->second, columnTypeName(ctype->second), options));
    } else if (cid->second == "alias") {
      // Create associated views for table aliases.
      auto calias = column.find("alias");
      if (calias != column.end()) {
        views.insert(calias->second);
      }
    } else if (cid->second == "columnAlias" && cname != column.end()) {
      auto ctarget = column.find("target");
      if (ctarget == column.end()) {
        continue;
      }

      // Record the column in the set of columns.
      // This is required because SQLITE uses indexes to identify columns.
      // Use an UNKNOWN_TYPE as a pseudo-mask, since the type does not matter.
      pVtab->content->columns.push_back(
          std::make_tuple(cname->second, UNKNOWN_TYPE, ColumnOptions::HIDDEN));
      // Record a mapping of the requested column alias name.
      size_t target_index = 0;
      for (size_t i = 0; i < pVtab->content->columns.size(); i++) {
        const auto& target_column = pVtab->content->columns[i];
        if (std::get<0>(target_column) == ctarget->second) {
          target_index = i;
          break;
        }
      }
      pVtab->content->aliases[cname->second] = target_index;
    } else if (cid->second == "attributes") {
      auto cattr = column.find("attributes");
      // Store the attributes locally so they may be passed to the SQL object.
      if (cattr != column.end()) {
        auto attr = tryTo<long>(cattr->second);
        if (attr) {
          pVtab->content->attributes =
              static_cast<TableAttributes>(attr.take());
        }
      }
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
  if (!pCur->uses_generator && pCur->row >= pCur->rows.size()) {
    // Request row index greater than row set size.
    return SQLITE_ERROR;
  }

  TableRowHolder& row =
      pCur->uses_generator ? pCur->current : pCur->rows[pCur->row];
  return row->get_column(ctx, cur->pVtab, col);
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
  double cost = kMaxIndexCost;

  // Tables may have requirements or use indexes.
  bool hasRequiredColumns = false;
  bool hasRequiredConstraints = false;

  // Expressions operating on the same virtual table are loosely identified by
  // the consecutive sets of terms each of the constraint sets are applied onto.
  // Subsequent attempts from failed (unusable) constraints replace the set,
  // while new sets of terms append.
  if (pIdxInfo->nConstraint > 0) {
    for (size_t i = 0; i < static_cast<size_t>(pIdxInfo->nConstraint); ++i) {
      // Record the term index (this index exists across all expressions).
      const auto& constraint_info = pIdxInfo->aConstraint[i];
      if (FLAGS_planner) {
        plan("xBestIndex Evaluating constraints for table: " +
             pVtab->content->name + " [index=" + std::to_string(i) +
             " column=" + std::to_string(constraint_info.iColumn) +
             " term=" + std::to_string((int)constraint_info.iTermOffset) +
             " usable=" + std::to_string((int)constraint_info.usable) + "]");
      }
      if (!constraint_info.usable) {
        continue;
      }

      // Lookup the column name given an index into the table column set.
      if (constraint_info.iColumn < 0 ||
          static_cast<size_t>(constraint_info.iColumn) >=
              pVtab->content->columns.size()) {
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
        hasRequiredConstraints = true;
        cost = 1;
      } else if (options & (ColumnOptions::INDEX | ColumnOptions::ADDITIONAL)) {
        cost = 1;
      } else {
        // not indexed, let sqlite filter it
        continue;
      }

      // Save a pair of the name and the constraint operator.
      // Use this constraint during xFilter by performing a scan and column
      // name lookup through out all cursor constraint lists.
      constraints.push_back(
          std::make_pair(name, Constraint(constraint_info.op)));

      // important: if we specify an index, it means xFilter will be called
      // once for every row.  So if you have an IN() list with 50 items,
      // xFilter will get called 50 times, once for each item.  If you have
      // a JOIN with 500 rows, xFilter is called 500 times.  Therefore,
      // when a spec file specifies a column to be required or index, the
      // table implementation must be able to quickly find and return a
      // single row. See issue 5379.

      pIdxInfo->aConstraintUsage[i].argvIndex = static_cast<int>(++expr_index);

      if (FLAGS_planner) {
        plan("xBestIndex Adding index constraint for table: " +
             pVtab->content->name + " [column=" + name +
             " arg_index=" + std::to_string(expr_index) +
             " op=" + std::to_string(constraint_info.op) + "]");
      }
    }
  }

  // track columns used
  UsedColumns colsUsed;
  UsedColumnsBitset colsUsedBitset(pIdxInfo->colUsed);
  if (colsUsedBitset.any()) {
    for (size_t i = 0; i < columns.size(); i++) {
      // Check whether the column is used. colUsed has one bit for each of the
      // first 63 columns, and the 64th bit indicates that at least one other
      // column is used.

      auto bit = i < 63 ? i : 63U;
      if (!colsUsedBitset[bit]) {
        continue;
      }

      auto column_name = std::get<0>(columns[i]);
      if (pVtab->content->aliases.count(column_name)) {
        colsUsedBitset.reset(bit);
        auto real_column_index = pVtab->content->aliases[column_name];
        bit = real_column_index < 63 ? real_column_index : 63U;
        colsUsedBitset.set(bit);
        column_name = std::get<0>(columns[real_column_index]);
      }
      colsUsed.insert(column_name);

      const auto& options = std::get<2>(columns[i]);
      if (options & ColumnOptions::REQUIRED) {
        hasRequiredColumns = true;
      }
    }
  }

  // Return max-cost if a required constraint is not present.
  // For example, you can't do a hash of a file if path not provided.
  if (hasRequiredColumns && !hasRequiredConstraints) {
    cost = kMaxIndexCost;
  }

  pIdxInfo->idxNum = static_cast<int>(kConstraintIndexID++);
  if (FLAGS_planner) {
    plan("xBestIndex Recording constraint set for table: " +
         pVtab->content->name + " [cost=" + std::to_string(cost) +
         " size=" + std::to_string(constraints.size()) +
         " idx=" + std::to_string(pIdxInfo->idxNum) + "]");
  }
  // Add the constraint set to the table's tracked constraints.
  pVtab->content->constraints[pIdxInfo->idxNum] = std::move(constraints);
  pVtab->content->colsUsed[pIdxInfo->idxNum] = std::move(colsUsed);
  pVtab->content->colsUsedBitsets[pIdxInfo->idxNum] = colsUsedBitset;
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
  auto content = pVtab->content;
  if (FLAGS_table_delay > 0 && pVtab->instance->tableCalled(*content)) {
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
  if (FLAGS_planner) {
    plan("xFilter Filtering called for table: " + content->name +
         " [constraint_count=" + std::to_string(content->constraints.size()) +
         " argc=" + std::to_string(argc) + " idx=" + std::to_string(idxNum) +
         "]");
  }

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
        if (FLAGS_planner) {
          plan("xFilter Adding constraint to cursor (" +
               std::to_string(pCur->id) + "): " + constraint.first + " " +
               opString(constraint.second.op) + " " + constraint.second.expr);
        }
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

  if (!content->colsUsedBitsets.empty()) {
    context.colsUsedBitset = content->colsUsedBitsets[idxNum];
  } else {
    // Unspecified; have to assume all columns are used
    context.colsUsedBitset->set();
  }
  if (content->colsUsed.size() > 0) {
    context.colsUsed = content->colsUsed[idxNum];
  }

  // Reset the virtual table contents.
  pCur->rows.clear();
  options.clear();

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
  if ((!user_based_satisfied || !required_satisfied || !events_satisfied)) {
    if (isShell()) {
      LOG(WARNING) << "Please see the table documentation: "
                   << table_doc(pVtab->content->name);
    }

    // Return early if constraints do not make sense.
    if (!required_satisfied) {
      return SQLITE_CONSTRAINT;
    }
  }

  // Generate the row data set.
  plan("Scanning rows for cursor (" + std::to_string(pCur->id) + ")");
  if (Registry::get().exists("table", pVtab->content->name, true)) {
    auto plugin = Registry::get().plugin("table", pVtab->content->name);
    auto table = std::dynamic_pointer_cast<TablePlugin>(plugin);
    try {
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
      pCur->rows = table->generate(context);
    } catch (const std::exception& e) {
      LOG(ERROR) << "Exception while executing table " << pVtab->content->name
                 << ": " << e.what();
      setTableErrorMessage(pVtabCursor->pVtab, e.what());
      if (FLAGS_table_exceptions) {
        throw;
      }
      return SQLITE_ERROR;
    }
  } else {
    PluginRequest request = {{"action", "generate"}};
    TablePlugin::setRequestFromContext(context, request);
    QueryData qd;
    auto status = Registry::call("table", pVtab->content->name, request, qd);
    if (!status.ok()) {
      VLOG(1) << "Invalid response from the extension table. Error "
              << status.getCode() << ": " << status.getMessage();
      setTableErrorMessage(pVtabCursor->pVtab, status.getMessage());
      return SQLITE_ERROR;
    }
    pCur->rows = tableRowsFromQueryData(std::move(qd));
  }

  // Set the number of rows.
  pCur->n = pCur->rows.size();

  if (FLAGS_planner) {
    plan("xFilter " + pVtab->content->name +
         " generate returned row count:" + std::to_string(pCur->n));
  }

  return SQLITE_OK;
}

struct sqlite3_module* getVirtualTableModule(const std::string& table_name,
                                             bool extension) {
  UpgradeLock lock(sqlite_module_map_mutex);

  if (sqlite_module_map.find(table_name) != sqlite_module_map.end()) {
    return &sqlite_module_map[table_name];
  }

  WriteUpgradeLock wlock(lock);

  sqlite_module_map[table_name] = {};
  sqlite_module_map[table_name].xCreate = tables::sqlite::xCreate;
  sqlite_module_map[table_name].xConnect = tables::sqlite::xCreate;
  sqlite_module_map[table_name].xBestIndex = tables::sqlite::xBestIndex;
  sqlite_module_map[table_name].xDisconnect = tables::sqlite::xDestroy;
  sqlite_module_map[table_name].xDestroy = tables::sqlite::xDestroy;
  sqlite_module_map[table_name].xOpen = tables::sqlite::xOpen;
  sqlite_module_map[table_name].xClose = tables::sqlite::xClose;
  sqlite_module_map[table_name].xFilter = tables::sqlite::xFilter;
  sqlite_module_map[table_name].xNext = tables::sqlite::xNext;
  sqlite_module_map[table_name].xEof = tables::sqlite::xEof;
  sqlite_module_map[table_name].xColumn = tables::sqlite::xColumn;
  sqlite_module_map[table_name].xRowid = tables::sqlite::xRowid;

  // Allow the table to receive INSERT/UPDATE/DROP events if it is
  // implemented from an extension and is overwriting the right methods
  // in the TablePlugin class
  if (extension) {
    extension_table_list.insert(table_name);
    sqlite_module_map[table_name].xUpdate = tables::sqlite::xUpdate;
  }

  return &sqlite_module_map[table_name];
}
} // namespace sqlite
} // namespace tables

Status attachTableInternal(const std::string& name,
                           const std::string& statement,
                           const SQLiteDBInstanceRef& instance,
                           bool is_extension) {
  if (SQLiteDBManager::isDisabled(name)) {
    VLOG(1) << "Table " << name << " is disabled, not attaching";
    return Status(0, getStringForSQLiteReturnCode(0));
  }

  struct sqlite3_module* module =
      tables::sqlite::getVirtualTableModule(name, is_extension);
  if (module == nullptr) {
    VLOG(1) << "Failed to retrieve the virtual table module for \"" << name
            << "\"";
    return Status(1);
  }

  // Note, if the clientData API is used then this will save a registry call
  // within xCreate.
  auto lock(instance->attachLock());

  int rc = sqlite3_create_module(
      instance->db(), name.c_str(), module, (void*)&(*instance));

  if (rc == SQLITE_OK || rc == SQLITE_MISUSE) {
    auto format =
        "CREATE VIRTUAL TABLE temp." + name + " USING " + name + statement;

    rc =
        sqlite3_exec(instance->db(), format.c_str(), nullptr, nullptr, nullptr);

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
  bool is_extension = false;

  for (const auto& name : RegistryFactory::get().names("table")) {
    // Column information is nice for virtual table create call.
    auto status =
        Registry::call("table", name, {{"action", "columns"}}, response);
    if (status.ok()) {
      auto statement = columnDefinition(response, true, is_extension);
      attachTableInternal(name, statement, instance, is_extension);
    }
  }
}
} // namespace osquery
