/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/json/json.h>

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/conversions/tryto.h>

#include <climits>

namespace osquery {

FLAG(bool, disable_caching, false, "Disable scheduled query caching");

CREATE_LAZY_REGISTRY(TablePlugin, "table");

uint64_t TablePlugin::kCacheInterval = 0;
uint64_t TablePlugin::kCacheStep = 0;

#define kDisableRowId "WITHOUT ROWID"

// Columns used bitmask
// https://stackoverflow.com/questions/1392059/algorithm-to-generate-bit-mask
template <typename R>
static constexpr R bitmask(unsigned int const onecount) {
  return static_cast<R>(-(onecount != 0)) &
         (static_cast<R>(-1) >> ((sizeof(R) * CHAR_BIT) - onecount));
}

Status TablePlugin::addExternal(const std::string& name,
                                const PluginResponse& response) {
  // Attach the table.
  if (response.size() == 0) {
    // Invalid table route info.
    // Tables must broadcast their column information, this is used while the
    // core is deciding if the extension's route is valid.
    return Status(1, "Invalid route info");
  }

  // Use the SQL registry to attach the name/definition.
  return Registry::call("sql", "sql", {{"action", "attach"}, {"table", name}});
}

void TablePlugin::removeExternal(const std::string& name) {
  // Detach the table name.
  Registry::call("sql", "sql", {{"action", "detach"}, {"table", name}});
}

void TablePlugin::setRequestFromContext(const QueryContext& context,
                                        PluginRequest& request) {
  auto doc = JSON::newObject();
  auto constraints = doc.getArray();

  // The QueryContext contains a constraint map from column to type information
  // and the list of operand/expression constraints applied to that column from
  // the query given.
  for (const auto& constraint : context.constraints) {
    auto child = doc.getObject();
    doc.addRef("name", constraint.first, child);
    constraint.second.serialize(doc, child);
    doc.push(child, constraints);
  }

  doc.add("constraints", constraints);

  if (context.colsUsed) {
    auto colsUsed = doc.getArray();
    for (const auto& columnName : *context.colsUsed) {
      doc.pushCopy(columnName, colsUsed);
    }
    doc.add("colsUsed", colsUsed);
  }

  if (context.colsUsedBitset) {
    doc.add("colsUsedBitset", context.colsUsedBitset->to_ullong());
  }

  doc.toString(request["context"]);
}

QueryContext TablePlugin::getContextFromRequest(
    const PluginRequest& request) const {
  QueryContext context;
  if (request.count("context") == 0) {
    return context;
  }

  auto doc = JSON::newObject();
  doc.fromString(request.at("context"));

  deserializeQueryContextJSON(doc, context);

  if (!doc.doc().HasMember("colsUsedBitset") && context.colsUsed) {
    context.colsUsedBitset = usedColumnsToBitset(*context.colsUsed);
  }

  return context;
}

UsedColumnsBitset TablePlugin::usedColumnsToBitset(
    const UsedColumns usedColumns) const {
  UsedColumnsBitset result;

  const auto& columns = this->columns();
  const auto& aliases = this->aliasedColumns();
  for (size_t i = 0; i < columns.size(); i++) {
    auto column_name = std::get<0>(columns[i]);
    const auto& aliased_name = aliases.find(column_name);
    if (aliased_name != aliases.end()) {
      column_name = aliased_name->second;
    }
    if (usedColumns.find(column_name) != usedColumns.end()) {
      result.set(i);
    }
  }

  return result;
}

Status TablePlugin::call(const PluginRequest& request,
                         PluginResponse& response) {
  response.clear();

  // TablePlugin API calling requires an action.
  if (request.count("action") == 0) {
    return Status(1, "Table plugins must include a request action");
  }

  const auto& action = request.at("action");

  if (action == "generate") {
    auto context = getContextFromRequest(request);
    TableRows result = generate(context);
    response = tableRowsToPluginResponse(result);
  } else if (action == "delete") {
    auto context = getContextFromRequest(request);
    response = delete_(context, request);
  } else if (action == "insert") {
    auto context = getContextFromRequest(request);
    response = insert(context, request);
  } else if (action == "update") {
    auto context = getContextFromRequest(request);
    response = update(context, request);
  } else if (action == "columns") {
    response = routeInfo();
  } else {
    return Status(1, "Unknown table plugin action: " + action);
  }

  return Status::success();
}

std::string TablePlugin::columnDefinition(bool is_extension) const {
  return osquery::columnDefinition(columns(), is_extension);
}

PluginResponse TablePlugin::routeInfo() const {
  // Route info consists of the serialized column information.
  PluginResponse response;
  for (const auto& column : columns()) {
    response.push_back(
        {{"id", "column"},
         {"name", std::get<0>(column)},
         {"type", columnTypeName(std::get<1>(column))},
         {"op", INTEGER(static_cast<size_t>(std::get<2>(column)))}});
  }
  // Each table name alias is provided such that the core may add the views.
  // These views need to be removed when the backing table is detached.
  for (const auto& alias : aliases()) {
    response.push_back({{"id", "alias"}, {"alias", alias}});
  }

  // Each column alias must be provided, additionally to the column's option.
  // This sets up the value-replacement move within the SQL implementation.
  for (const auto& target : columnAliases()) {
    for (const auto& alias : target.second) {
      response.push_back(
          {{"id", "columnAlias"}, {"name", alias}, {"target", target.first}});
    }
  }

  response.push_back(
      {{"id", "attributes"},
       {"attributes", INTEGER(static_cast<size_t>(attributes()))}});
  return response;
}

static bool cacheAllowed(const TableColumns& cols, const QueryContext& ctx) {
  if (!ctx.useCache() || !ctx.defaultColumnsUsed()) {
    // The query execution did not request use of the warm cache.
    return false;
  }

  auto uncachable = ColumnOptions::INDEX | ColumnOptions::REQUIRED |
                    ColumnOptions::ADDITIONAL | ColumnOptions::OPTIMIZED;
  for (const auto& column : cols) {
    auto opts = std::get<2>(column) & uncachable;
    if (opts && ctx.constraints.at(std::get<0>(column)).exists()) {
      return false;
    }
  }
  return true;
}

bool TablePlugin::isCached(uint64_t step, const QueryContext& ctx) const {
  if (FLAGS_disable_caching) {
    return false;
  }

  // Perform the step comparison first, because it's easy.
  return (step < last_cached_ + last_interval_ && cacheAllowed(columns(), ctx));
}

TableRows TablePlugin::getCache() const {
  VLOG(1) << "Retrieving results from cache for table: " << getName();
  // Lookup results from database and deserialize.
  std::string content;
  getDatabaseValue(kQueries, "cache." + getName(), content);
  TableRows results;
  deserializeTableRowsJSON(content, results);
  return results;
}

void TablePlugin::setCache(uint64_t step,
                           uint64_t interval,
                           const QueryContext& ctx,
                           const TableRows& results) {
  if (FLAGS_disable_caching || !cacheAllowed(columns(), ctx)) {
    return;
  }

  // Serialize QueryData and save to database.
  std::string content;
  if (serializeTableRowsJSON(results, content)) {
    last_cached_ = step;
    last_interval_ = interval;
    setDatabaseValue(kQueries, "cache." + getName(), content);
  }
}

std::string columnDefinition(const TableColumns& columns, bool is_extension) {
  std::map<std::string, bool> epilog;
  bool indexed = false;
  std::vector<std::string> pkeys;

  std::string statement = "(";
  for (size_t i = 0; i < columns.size(); ++i) {
    const auto& column = columns.at(i);
    statement +=
        '`' + std::get<0>(column) + "` " + columnTypeName(std::get<1>(column));
    auto& options = std::get<2>(column);
    if (options & ColumnOptions::INDEX) {
      indexed = true;
    }
    if (options & (ColumnOptions::INDEX | ColumnOptions::ADDITIONAL)) {
      pkeys.push_back(std::get<0>(column));
      epilog[kDisableRowId] = true;
    }
    if (options & ColumnOptions::HIDDEN) {
      statement += " HIDDEN";
    }
    if (options & ColumnOptions::COLLATENOCASE) {
      statement += " COLLATE NOCASE";
    }
    if (i < columns.size() - 1) {
      statement += ", ";
    }
  }

  // If there are only 'additional' columns (rare), pkey is the 'unique row'.
  // Otherwise an additional constraint will create duplicate rowids.
  if (!indexed && epilog[kDisableRowId]) {
    pkeys.clear();
    for (const auto& column : columns) {
      pkeys.push_back(std::get<0>(column));
    }
  }

  // Append the primary keys, if any were defined.
  if (!pkeys.empty()) {
    statement += ", PRIMARY KEY (";
    for (auto pkey = pkeys.begin(); pkey != pkeys.end();) {
      statement += '`' + std::move(*pkey) + '`';
      if (++pkey != pkeys.end()) {
        statement += ", ";
      }
    }
    statement += ')';
  }

  // Tables implemented by extension can be made read/write; make sure to always
  // keep the rowid column, as we need it to reference rows when handling UPDATE
  // and DELETE queries
  if (is_extension) {
    epilog[kDisableRowId] = false;
  }

  statement += ')';
  for (auto& ei : epilog) {
    if (ei.second) {
      statement += ' ' + std::move(ei.first);
    }
  }
  return statement;
}

std::string columnDefinition(const PluginResponse& response,
                             bool aliases,
                             bool is_extension) {
  TableColumns columns;
  // Maintain a map of column to the type, for alias type lookups.
  std::map<std::string, ColumnType> column_types;
  for (const auto& column : response) {
    auto id = column.find("id");
    if (id == column.end()) {
      continue;
    }

    auto cname = column.find("name");
    auto ctype = column.find("type");
    if (id->second == "column" && cname != column.end() &&
        ctype != column.end()) {
      auto options = ColumnOptions::DEFAULT;

      auto cop = column.find("op");
      if (cop != column.end()) {
        auto op = tryTo<int>(cop->second);
        if (op) {
          options = static_cast<ColumnOptions>(op.take());
        }
      }
      auto column_type = columnTypeName(ctype->second);
      columns.push_back(make_tuple(cname->second, column_type, options));
      if (aliases) {
        column_types[cname->second] = column_type;
      }
    } else if (id->second == "columnAlias" && cname != column.end() &&
               aliases) {
      auto ctarget = column.find("target");
      if (ctarget != column.end()) {
        auto target_ctype = column_types.find(ctarget->second);
        if (target_ctype != column_types.end()) {
          columns.push_back(make_tuple(
              cname->second, target_ctype->second, ColumnOptions::HIDDEN));
        }
      }
    }
  }
  return columnDefinition(columns, is_extension);
}

ColumnType columnTypeName(const std::string& type) {
  for (const auto& col : kColumnTypeNames) {
    if (col.second == type) {
      return col.first;
    }
  }
  return UNKNOWN_TYPE;
}

bool ConstraintList::exists(const ConstraintOperatorFlag ops) const {
  if (ops == ANY_OP) {
    return (constraints_.size() > 0);
  } else {
    for (const struct Constraint& c : constraints_) {
      if (c.op & ops) {
        return true;
      }
    }
    return false;
  }
}

bool ConstraintList::matches(const std::string& expr) const {
  // Support each SQL affinity type casting.
  if (affinity == TEXT_TYPE) {
    return literal_matches<TEXT_LITERAL>(expr);
  } else if (affinity == INTEGER_TYPE) {
    auto lexpr = tryTo<INTEGER_LITERAL>(expr);
    if (lexpr) {
      return literal_matches<INTEGER_LITERAL>(lexpr.take());
    }
  } else if (affinity == BIGINT_TYPE) {
    auto lexpr = tryTo<BIGINT_LITERAL>(expr);
    if (lexpr) {
      return literal_matches<BIGINT_LITERAL>(lexpr.take());
    }
  } else if (affinity == UNSIGNED_BIGINT_TYPE) {
    auto lexpr = tryTo<UNSIGNED_BIGINT_LITERAL>(expr);
    if (lexpr) {
      return literal_matches<UNSIGNED_BIGINT_LITERAL>(lexpr.take());
    }
  }

  return false;
}

template <typename T>
bool ConstraintList::literal_matches(const T& base_expr) const {
  bool aggregate = true;
  for (size_t i = 0; i < constraints_.size(); ++i) {
    auto constraint_expr = tryTo<T>(constraints_[i].expr);
    if (!constraint_expr) {
      // Cannot cast input constraint to column type.
      return false;
    }
    if (constraints_[i].op == EQUALS) {
      aggregate = aggregate && (base_expr == constraint_expr.take());
    } else if (constraints_[i].op == GREATER_THAN) {
      aggregate = aggregate && (base_expr > constraint_expr.take());
    } else if (constraints_[i].op == LESS_THAN) {
      aggregate = aggregate && (base_expr < constraint_expr.take());
    } else if (constraints_[i].op == GREATER_THAN_OR_EQUALS) {
      aggregate = aggregate && (base_expr >= constraint_expr.take());
    } else if (constraints_[i].op == LESS_THAN_OR_EQUALS) {
      aggregate = aggregate && (base_expr <= constraint_expr.take());
    } else {
      // Unsupported constraint. Should match every thing.
      return true;
    }
    if (!aggregate) {
      // Speed up comparison.
      return false;
    }
  }
  return true;
}

std::set<std::string> ConstraintList::getAll(ConstraintOperator op) const {
  std::set<std::string> set;
  for (size_t i = 0; i < constraints_.size(); ++i) {
    if (constraints_[i].op == op) {
      // TODO: this does not apply a distinct.
      set.insert(constraints_[i].expr);
    }
  }
  return set;
}

template <typename T>
std::set<T> ConstraintList::getAll(ConstraintOperator /* op */) const {
  std::set<T> cs;
  for (const auto& item : constraints_) {
    auto exp = tryTo<T>(item.expr);
    if (exp) {
      cs.insert(exp.take());
    }
  }
  return cs;
}

template <>
std::set<std::string> ConstraintList::getAll(ConstraintOperator op) const {
  return getAll(op);
}

/// Explicit getAll for INTEGER.
template std::set<INTEGER_LITERAL> ConstraintList::getAll<int>(
    ConstraintOperator) const;

/// Explicit getAll for BIGINT.
template std::set<long long> ConstraintList::getAll<long long>(
    ConstraintOperator) const;

/// Explicit getAll for UNSIGNED_BIGINT.
template std::set<unsigned long long>
    ConstraintList::getAll<unsigned long long>(ConstraintOperator) const;

void ConstraintList::serialize(JSON& doc, rapidjson::Value& obj) const {
  auto expressions = doc.getArray();
  for (const auto& constraint : constraints_) {
    auto child = doc.getObject();
    doc.add("op", static_cast<size_t>(constraint.op), child);
    doc.addRef("expr", constraint.expr, child);
    doc.push(child, expressions);
  }
  doc.add("list", expressions, obj);
  doc.addCopy("affinity", columnTypeName(affinity), obj);
}

void ConstraintList::deserialize(const rapidjson::Value& obj) {
  // Iterate through the list of operand/expressions, then set the constraint
  // type affinity.
  if (!obj.IsObject() || !obj.HasMember("list") || !obj["list"].IsArray()) {
    return;
  }

  for (const auto& list : obj["list"].GetArray()) {
    auto op = static_cast<unsigned char>(JSON::valueToSize(list["op"]));
    Constraint constraint(op);
    constraint.expr = list["expr"].GetString();
    constraints_.push_back(constraint);
  }

  auto affinity_name = (obj.HasMember("affinity") && obj["affinity"].IsString())
                           ? obj["affinity"].GetString()
                           : "UNKNOWN";
  affinity = columnTypeName(affinity_name);
}

bool QueryContext::isColumnUsed(const std::string& colName) const {
  return !colsUsed || colsUsed->find(colName) != colsUsed->end();
}

bool QueryContext::isAnyColumnUsed(
    std::initializer_list<std::string> colNames) const {
  for (auto& colName : colNames) {
    if (isColumnUsed(colName)) {
      return true;
    }
  }
  return false;
}

bool QueryContext::defaultColumnsUsed() const {
  auto mask = bitmask<uint64_t>(table_->columns.size());
  return !colsUsedBitset || *colsUsedBitset == mask;
}

void QueryContext::useCache(bool use_cache) {
  use_cache_ = use_cache;
}

bool QueryContext::useCache() const {
  return use_cache_;
}

void QueryContext::setCache(const std::string& index,
                            const TableRowHolder& cache) {
  table_->cache[index] = cache->clone();
}

bool QueryContext::isCached(const std::string& index) const {
  return (table_->cache.count(index) != 0);
}

TableRowHolder QueryContext::getCache(const std::string& index) {
  return table_->cache[index]->clone();
}

bool QueryContext::hasConstraint(const std::string& column,
                                 ConstraintOperator op) const {
  if (constraints.count(column) == 0) {
    return false;
  }
  return constraints.at(column).exists(op);
}

Status QueryContext::expandConstraints(
    const std::string& column,
    ConstraintOperator op,
    std::set<std::string>& output,
    std::function<Status(const std::string& constraint,
                         std::set<std::string>& output)> predicate) {
  for (const auto& constraint : constraints[column].getAll(op)) {
    auto status = predicate(constraint, output);
    if (!status) {
      return status;
    }
  }
  return Status(0);
}

Status deserializeQueryContextJSON(const JSON& json_helper,
                                   QueryContext& context) {
  const auto& rapidjson_doc = json_helper.doc();

  if (rapidjson_doc.HasMember("colsUsed")) {
    UsedColumns cols_used;
    for (const auto& column_name : rapidjson_doc["colsUsed"].GetArray()) {
      cols_used.insert(column_name.GetString());
    }
    context.colsUsed = cols_used;
  }

  if (rapidjson_doc.HasMember("colsUsedBitset")) {
    context.colsUsedBitset = rapidjson_doc["colsUsedBitset"].GetUint64();
  }

  if (!rapidjson_doc.HasMember("constraints")) {
    return Status::failure(1, "Missing contraints field in JSON");
  }

  if (!rapidjson_doc["constraints"].IsArray()) {
    return Status::failure(1, "contraints field not a JSON array");
  }

  // Set the context limit and deserialize each column constraint list.
  for (const auto& constraint : rapidjson_doc["constraints"].GetArray()) {
    auto column_name = constraint["name"].GetString();
    context.constraints[column_name].deserialize(constraint);
  }

  return Status::success();
}

void serializeQueryContextJSON(const QueryContext& context, JSON& json_helper) {
  json_helper = JSON::newObject();
  auto constraints = json_helper.getArray();

  // The QueryContext contains a constraint map from column to type information
  // and the list of operand/expression constraints applied to that column from
  // the query given.
  for (const auto& constraint : context.constraints) {
    auto child = json_helper.getObject();
    json_helper.addRef("name", constraint.first, child);
    constraint.second.serialize(json_helper, child);
    json_helper.push(child, constraints);
  }

  json_helper.add("constraints", constraints);

  if (context.colsUsed) {
    auto cols_used = json_helper.getArray();
    for (const auto& column_name : *context.colsUsed) {
      json_helper.pushCopy(column_name, cols_used);
    }
    json_helper.add("colsUsed", cols_used);
  }

  if (context.colsUsedBitset) {
    json_helper.add("colsUsedBitset", context.colsUsedBitset->to_ullong());
  }
}

} // namespace osquery
