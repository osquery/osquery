/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/json.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(bool, disable_caching, false, "Disable scheduled query caching");

CREATE_LAZY_REGISTRY(TablePluginBase, "table");

const std::map<ColumnType, std::string> kColumnTypeNames = {
    {UNKNOWN_TYPE, "UNKNOWN"},
    {TEXT_TYPE, "TEXT"},
    {INTEGER_TYPE, "INTEGER"},
    {BIGINT_TYPE, "BIGINT"},
    {UNSIGNED_BIGINT_TYPE, "UNSIGNED BIGINT"},
    {DOUBLE_TYPE, "DOUBLE"},
    {BLOB_TYPE, "BLOB"},
};

/**
 * @brief Constructor for TablePluginBase
 * Initializes cache_ with a new instance, enabled only if attributes
 * include CACHEABLE.
 */
TablePluginBase::TablePluginBase(const TableDefinition& tdef)
    : Plugin(),
      tableDef_(tdef),
      cache_(*TableCacheNew(tdef.name,
                            (tdef.attributes & TableAttributes::CACHEABLE))) {}

Status TablePluginBase::addExternal(const std::string& name,
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

void TablePluginBase::removeExternal(const std::string& name) {
  // Detach the table name.
  Registry::call("sql", "sql", {{"action", "detach"}, {"table", name}});
}

void TablePluginBase::setRequestFromContext(const QueryContext& context,
                                            PluginRequest& request) {
  pt::ptree tree;

  // The QueryContext contains a constraint map from column to type information
  // and the list of operand/expression constraints applied to that column from
  // the query given.
  pt::ptree constraints;
  for (const auto& constraint : context.constraints) {
    pt::ptree child;
    child.put("name", constraint.first);
    constraint.second.serialize(child);
    constraints.push_back(std::make_pair("", child));
  }
  tree.add_child("constraints", constraints);

  // Write the property tree as a JSON string into the PluginRequest.
  std::ostringstream output;
  try {
    pt::write_json(output, tree, false);
  } catch (const pt::json_parser::json_parser_error& /* e */) {
    // The content could not be represented as JSON.
  }
  request["context"] = output.str();
}

void TablePluginBase::setContextFromRequest(const PluginRequest& request,
                                            QueryContext& context) {
  if (request.count("context") == 0) {
    return;
  }

  // Read serialized context from PluginRequest.
  pt::ptree tree;
  try {
    std::stringstream input;
    input << request.at("context");
    pt::read_json(input, tree);
  } catch (const pt::json_parser::json_parser_error& /* e */) {
    return;
  }

  // Set the context limit and deserialize each column constraint list.
  for (const auto& constraint : tree.get_child("constraints")) {
    auto column_name = constraint.second.get<std::string>("name");
    context.constraints[column_name].unserialize(constraint.second);
  }
}

Status TablePluginBase::call(const PluginRequest& request,
                             PluginResponse& response) {
  response.clear();
  // TablePlugin API calling requires an action.
  if (request.count("action") == 0) {
    return Status(1, "Table plugins must include a request action");
  }

  if (request.at("action") == "generate") {
    // The "generate" action runs the table implementation using a PluginRequest
    // with optional serialized QueryContext and returns the QueryData results
    // as the PluginRequest data.

    // Create a fake table implementation for caching.
    QueryContext context;
    if (request.count("context") > 0) {
      setContextFromRequest(request, context);
    }
    response = generate(context);
  } else if (request.at("action") == "columns") {
    // The "columns" action returns a PluginRequest filled with column
    // information such as name and type.
    response = routeInfo();
  } else {
    return Status(1, "Unknown table plugin action: " + request.at("action"));
  }

  return Status(0, "OK");
}

PluginResponse TablePluginBase::routeInfo() const {
  // Route info consists of the serialized column information.
  PluginResponse response;
  for (const auto& column : definition().columns) {
    response.push_back(
        {{"id", "column"},
         {"name", std::get<0>(column)},
         {"type", columnTypeName(std::get<1>(column))},
         {"op", INTEGER(static_cast<size_t>(std::get<2>(column)))}});
  }
  // Each table name alias is provided such that the core may add the views.
  // These views need to be removed when the backing table is detached.
  for (const auto& alias : definition().aliases) {
    response.push_back({{"id", "alias"}, {"alias", alias}});
  }

  // Each column alias must be provided, additionally to the column's option.
  // This sets up the value-replacement move within the SQL implementation.
  for (const auto& target : definition().columnAliases) {
    for (const auto& alias : target.second) {
      response.push_back(
          {{"id", "columnAlias"}, {"name", alias}, {"target", target.first}});
    }
  }

  response.push_back(
      {{"id", "attributes"},
       {"attributes", INTEGER(static_cast<size_t>(definition().attributes))}});
  return response;
}

bool TablePlugin::isCached(size_t interval, const QueryContext& ctx) const {
  assert(false);
  return false;
}

void TablePlugin::setCache(size_t step,
                           size_t interval,
                           const QueryContext& ctx,
                           const QueryData& results) {}

std::string columnDefinition(const TableColumns& columns) {
  std::map<std::string, bool> epilog;
  bool indexed = false;
  std::vector<std::string> pkeys;

  std::string statement = "(";
  for (size_t i = 0; i < columns.size(); ++i) {
    const auto& column = columns.at(i);
    statement +=
        '`' + std::get<0>(column) + "` " + columnTypeName(std::get<1>(column));
    auto& options = std::get<2>(column);
    if (options & (ColumnOptions::INDEX | ColumnOptions::ADDITIONAL)) {
      if (options & ColumnOptions::INDEX) {
        indexed = true;
      }
      pkeys.push_back(std::get<0>(column));
      epilog["WITHOUT ROWID"] = true;
    }
    if (options & ColumnOptions::HIDDEN) {
      statement += " HIDDEN";
    }
    if (i < columns.size() - 1) {
      statement += ", ";
    }
  }

  // If there are only 'additional' columns (rare), do not attempt a pkey.
  if (!indexed) {
    epilog["WITHOUT ROWID"] = false;
    pkeys.clear();
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

  statement += ')';
  for (auto& ei : epilog) {
    if (ei.second) {
      statement += ' ' + std::move(ei.first);
    }
  }
  return statement;
}

std::string columnDefinition(const PluginResponse& response, bool aliases) {
  TableColumns columns;
  // Maintain a map of column to the type, for alias type lookups.
  std::map<std::string, ColumnType> column_types;
  for (const auto& column : response) {
    if (column.count("id") == 0) {
      continue;
    }

    if (column.at("id") == "column" && column.count("name") &&
        column.count("type")) {
      auto options =
          (column.count("op"))
              ? (ColumnOptions)AS_LITERAL(INTEGER_LITERAL, column.at("op"))
              : ColumnOptions::DEFAULT;
      auto column_type = columnTypeName(column.at("type"));
      columns.push_back(make_tuple(column.at("name"), column_type, options));
      if (aliases) {
        column_types[column.at("name")] = column_type;
      }
    } else if (column.at("id") == "columnAlias" && column.count("name") &&
               column.count("target") && aliases) {
      const auto& target = column.at("target");
      if (column_types.count(target) == 0) {
        // No type was defined for the alias target.
        continue;
      }
      columns.push_back(make_tuple(
          column.at("name"), column_types.at(target), ColumnOptions::HIDDEN));
    }
  }
  return columnDefinition(columns);
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
  try {
    if (affinity == TEXT_TYPE) {
      return literal_matches<TEXT_LITERAL>(expr);
    } else if (affinity == INTEGER_TYPE) {
      INTEGER_LITERAL lexpr = AS_LITERAL(INTEGER_LITERAL, expr);
      return literal_matches<INTEGER_LITERAL>(lexpr);
    } else if (affinity == BIGINT_TYPE) {
      BIGINT_LITERAL lexpr = AS_LITERAL(BIGINT_LITERAL, expr);
      return literal_matches<BIGINT_LITERAL>(lexpr);
    } else if (affinity == UNSIGNED_BIGINT_TYPE) {
      UNSIGNED_BIGINT_LITERAL lexpr = AS_LITERAL(UNSIGNED_BIGINT_LITERAL, expr);
      return literal_matches<UNSIGNED_BIGINT_LITERAL>(lexpr);
    }
  } catch (const boost::bad_lexical_cast& /* e */) {
    // Unsupported affinity type or unable to cast content type.
  }

  return false;
}

template <typename T>
bool ConstraintList::literal_matches(const T& base_expr) const {
  bool aggregate = true;
  for (size_t i = 0; i < constraints_.size(); ++i) {
    T constraint_expr = AS_LITERAL(T, constraints_[i].expr);
    if (constraints_[i].op == EQUALS) {
      aggregate = aggregate && (base_expr == constraint_expr);
    } else if (constraints_[i].op == GREATER_THAN) {
      aggregate = aggregate && (base_expr > constraint_expr);
    } else if (constraints_[i].op == LESS_THAN) {
      aggregate = aggregate && (base_expr < constraint_expr);
    } else if (constraints_[i].op == GREATER_THAN_OR_EQUALS) {
      aggregate = aggregate && (base_expr >= constraint_expr);
    } else if (constraints_[i].op == LESS_THAN_OR_EQUALS) {
      aggregate = aggregate && (base_expr <= constraint_expr);
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

void ConstraintList::serialize(boost::property_tree::ptree& tree) const {
  boost::property_tree::ptree expressions;
  for (const auto& constraint : constraints_) {
    boost::property_tree::ptree child;
    child.put("op", constraint.op);
    child.put("expr", constraint.expr);
    expressions.push_back(std::make_pair("", child));
  }
  tree.add_child("list", expressions);
  tree.put("affinity", columnTypeName(affinity));
}

void ConstraintList::unserialize(const boost::property_tree::ptree& tree) {
  // Iterate through the list of operand/expressions, then set the constraint
  // type affinity.
  for (const auto& list : tree.get_child("list")) {
    Constraint constraint(list.second.get<unsigned char>("op"));
    constraint.expr = list.second.get<std::string>("expr");
    constraints_.push_back(constraint);
  }
  affinity = columnTypeName(tree.get<std::string>("affinity", "UNKNOWN"));
}

void QueryContext::useCache(bool use_cache) {
  use_cache_ = use_cache;
}

bool QueryContext::useCache() const {
  return use_cache_;
}

void QueryContext::setCache(const std::string& index, Row _cache) {
  table_->cache[index] = std::move(_cache);
}

void QueryContext::setCache(const std::string& index,
                            const std::string& key,
                            std::string _item) {
  table_->cache[index][key] = std::move(_item);
}

bool QueryContext::isCached(const std::string& index) const {
  return (table_->cache.count(index) != 0);
}

const Row& QueryContext::getCache(const std::string& index) {
  return table_->cache[index];
}

const std::string& QueryContext::getCache(const std::string& index,
                                          const std::string& key) {
  return table_->cache[index][key];
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

/*
 * Implementation of TableCache for tables that should not be cached.
 */
class TableCacheDisabled : public TableCache {
 public:
  TableCacheDisabled(const std::string tableName) : tableName_(tableName) {}

  virtual ~TableCacheDisabled() {}

  virtual bool isEnabled() const {
    return false;
  }

  virtual const std::string getTableName() const {
    return tableName_;
  }

  virtual bool isCached() const {
    return false;
  }

  virtual QueryData get() const {
    return QueryData();
  }

  virtual void set(const QueryData& results) {}

 private:
  const std::string tableName_;
};

TableCache* TableCacheDisabledNew(std::string tableName) {
  return new TableCacheDisabled(tableName);
}
} // namespace osquery
