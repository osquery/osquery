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

#include <osquery/logger.h>
#include <osquery/tables.h>

namespace pt = boost::property_tree;

namespace osquery {

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
  pt::write_json(output, tree, false);
  request["context"] = output.str();
}

void TablePlugin::setResponseFromQueryData(const QueryData& data,
                                           PluginResponse& response) {
  response = std::move(data);
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
  context.limit = tree.get<int>("limit");
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
    setResponseFromQueryData(generate(context), response);
  } else if (request.at("action") == "columns") {
    // "columns" returns a PluginRequest filled with column information
    // such as name and type.
    const auto& column_list = columns();
    for (const auto& column : column_list) {
      response.push_back({{"name", column.first}, {"type", column.second}});
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
    response.push_back({{"name", column.first}, {"type", column.second}});
  }
  return response;
}

std::string columnDefinition(const TableColumns& columns) {
  std::string statement = "(";
  for (size_t i = 0; i < columns.size(); ++i) {
    statement += columns.at(i).first + " " + columns.at(i).second;
    if (i < columns.size() - 1) {
      statement += ", ";
    }
  }
  return statement += ")";
}

std::string columnDefinition(const PluginResponse& response) {
  TableColumns columns;
  for (const auto& column : response) {
    columns.push_back(make_pair(column.at("name"), column.at("type")));
  }
  return columnDefinition(columns);
}

bool ConstraintList::matches(const std::string& expr) const {
  // Support each SQL affinity type casting.
  if (affinity == "TEXT") {
    return literal_matches<TEXT_LITERAL>(expr);
  } else if (affinity == "INTEGER") {
    INTEGER_LITERAL lexpr = AS_LITERAL(INTEGER_LITERAL, expr);
    return literal_matches<INTEGER_LITERAL>(lexpr);
  } else if (affinity == "BIGINT") {
    BIGINT_LITERAL lexpr = AS_LITERAL(BIGINT_LITERAL, expr);
    return literal_matches<BIGINT_LITERAL>(lexpr);
  } else if (affinity == "UNSIGNED_BIGINT") {
    UNSIGNED_BIGINT_LITERAL lexpr = AS_LITERAL(UNSIGNED_BIGINT_LITERAL, expr);
    return literal_matches<UNSIGNED_BIGINT_LITERAL>(lexpr);
  } else {
    // Unsupprted affinity type.
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
  tree.put("affinity", affinity);
}

void ConstraintList::unserialize(const boost::property_tree::ptree& tree) {
  // Iterate through the list of operand/expressions, then set the constraint
  // type affinity.
  for (const auto& list : tree.get_child("list")) {
    Constraint constraint(list.second.get<unsigned char>("op"));
    constraint.expr = list.second.get<std::string>("expr");
    constraints_.push_back(constraint);
  }
  affinity = tree.get<std::string>("affinity");
}
}
