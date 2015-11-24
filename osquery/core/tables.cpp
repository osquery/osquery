/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/property_tree/json_parser.hpp>

#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace pt = boost::property_tree;

namespace osquery {

FLAG(bool, disable_caching, false, "Disable scheduled query caching");

size_t TablePlugin::kCacheInterval = 0;
size_t TablePlugin::kCacheStep = 0;

const std::map<ColumnType, std::string> kColumnTypeNames = {
    {UNKNOWN_TYPE, "UNKNOWN"},
    {TEXT_TYPE, "TEXT"},
    {INTEGER_TYPE, "INTEGER"},
    {BIGINT_TYPE, "BIGINT"},
    {UNSIGNED_BIGINT_TYPE, "UNSIGNED BIGINT"},
    {DOUBLE_TYPE, "DOUBLE"},
    {BLOB_TYPE, "BLOB"},
};

Status TablePlugin::addExternal(const std::string& name,
                                const PluginResponse& response) {
  // Attach the table.
  if (response.size() == 0) {
    // Invalid table route info.
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
  pt::ptree tree;
  tree.put("limit", context.limit);

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
  } catch (const pt::json_parser::json_parser_error& e) {
    // The content could not be represented as JSON.
  }
  request["context"] = output.str();
}

void TablePlugin::setContextFromRequest(const PluginRequest& request,
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
  } catch (const pt::json_parser::json_parser_error& e) {
    return;
  }

  // Set the context limit and deserialize each column constraint list.
  context.limit = tree.get<int>("limit", 0);
  for (const auto& constraint : tree.get_child("constraints")) {
    auto column_name = constraint.second.get<std::string>("name");
    context.constraints[column_name].unserialize(constraint.second);
  }
}

Status TablePlugin::call(const PluginRequest& request,
                         PluginResponse& response) {
  response.clear();
  // TablePlugin API calling requires an action.
  if (request.count("action") == 0) {
    return Status(1, "Table plugins must include a request action");
  }

  if (request.at("action") == "generate") {
    // "generate" runs the table implementation using a PluginRequest with
    // optional serialized QueryContext and returns the QueryData results as
    // the PluginRequest data.
    QueryContext context;
    if (request.count("context") > 0) {
      setContextFromRequest(request, context);
    }
    response = generate(context);
  } else if (request.at("action") == "columns") {
    // "columns" returns a PluginRequest filled with column information
    // such as name and type.
    const auto& column_list = columns();
    for (const auto& column : column_list) {
      response.push_back(
          {{"name", column.first}, {"type", columnTypeName(column.second)}});
    }
  } else if (request.at("action") == "definition") {
    response.push_back({{"definition", columnDefinition()}});
  } else {
    return Status(1, "Unknown table plugin action: " + request.at("action"));
  }

  return Status(0, "OK");
}

std::string TablePlugin::columnDefinition() const {
  return osquery::columnDefinition(columns());
}

PluginResponse TablePlugin::routeInfo() const {
  // Route info consists of only the serialized column information.
  PluginResponse response;
  for (const auto& column : columns()) {
    response.push_back(
        {{"name", column.first}, {"type", columnTypeName(column.second)}});
  }
  return response;
}

bool TablePlugin::isCached(size_t step) {
  return (!FLAGS_disable_caching && step < last_cached_ + last_interval_);
}

QueryData TablePlugin::getCache() const {
  VLOG(1) << "Retrieving results from cache for table: " << getName();
  // Lookup results from database and deserialize.
  std::string content;
  getDatabaseValue(kQueries, "cache." + getName(), content);
  QueryData results;
  deserializeQueryDataJSON(content, results);
  return results;
}

void TablePlugin::setCache(size_t step,
                           size_t interval,
                           const QueryData& results) {
  // Serialize QueryData and save to database.
  std::string content;
  if (!FLAGS_disable_caching && serializeQueryDataJSON(results, content)) {
    last_cached_ = step;
    last_interval_ = interval;
    setDatabaseValue(kQueries, "cache." + getName(), content);
  }
}

std::string columnDefinition(const TableColumns& columns) {
  std::string statement = "(";
  for (size_t i = 0; i < columns.size(); ++i) {
    statement +=
        "`" + columns.at(i).first + "` " + columnTypeName(columns.at(i).second);
    if (i < columns.size() - 1) {
      statement += ", ";
    }
  }
  return statement += ")";
}

std::string columnDefinition(const PluginResponse& response) {
  TableColumns columns;
  for (const auto& column : response) {
    columns.push_back(
        make_pair(column.at("name"), columnTypeName(column.at("type"))));
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
  } else {
    // Unsupported affinity type.
    return false;
  }
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
      // Unsupported constraint.
      return false;
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

bool QueryContext::hasConstraint(const std::string& column,
                                 ConstraintOperator op) const {
  if (constraints.count(column) == 0) {
    return false;
  }
  return constraints.at(column).exists(op);
}
}
