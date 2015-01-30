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

namespace osquery {
namespace tables {


bool ConstraintList::matches(const std::string& expr) {
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
bool ConstraintList::literal_matches(const T& base_expr) {
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

std::vector<std::string> ConstraintList::getAll(ConstraintOperator op) {
  std::vector<std::string> set;
  for (size_t i = 0; i < constraints_.size(); ++i) {
    if (constraints_[i].op == op) {
      // TODO: this does not apply a distinct.
      set.push_back(constraints_[i].expr);
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

void TablePlugin::setRequestFromContext(const QueryContext& context,
                                        PluginRequest& request) {
  boost::property_tree::ptree tree;
  tree.put("limit", context.limit);

  // The QueryContext contains a constraint map from column to type information
  // and the list of operand/expression constraints applied to that column from
  // the query given.
  boost::property_tree::ptree constraints;
  for (const auto& constraint : context.constraints) {
    boost::property_tree::ptree child;
    child.put("name", constraint.first);
    constraint.second.serialize(child);
    constraints.push_back(std::make_pair("", child));
  }
  tree.add_child("constraints", constraints);

  // Write the property tree as a JSON string into the PluginRequest.
  std::ostringstream output;
  boost::property_tree::write_json(output, tree, false);
  request["context"] = output.str();
}

void TablePlugin::setResponseFromQueryData(const QueryData& data,
                                           PluginResponse& response) {
  for (const auto& row : data) {
    response.push_back(row);
  }
}

void TablePlugin::setContextFromRequest(const PluginRequest& request,
                                        QueryContext& context) {
  if (request.count("context") == 0) {
    return;
  }

  // Read serialized context from PluginRequest.
  std::stringstream input;
  input << request.at("context");
  boost::property_tree::ptree tree;
  boost::property_tree::read_json(input, tree);

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

  if (request.at("action") == "statement") {
    // The "statement" action generates an SQL create table statement.
    response.push_back({{"statement", statement()}});
  } else if (request.at("action") == "generate") {
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
    auto column_list = columns();
    for (const auto& column : column_list) {
      response.push_back({{"name", column.first}, {"type", column.second}});
    }
  } else {
    return Status(1, "Unknown table plugin action: " + request.at("action"));
  }

  return Status(0, "OK");
}

std::string TablePlugin::statement() {
  auto column_list = columns();
  std::string statement = "CREATE TABLE " + name_ + "(";
  for (size_t i = 0; i < column_list.size(); ++i) {
    statement += column_list[i].first + " " + column_list[i].second;
    if (i < column_list.size() - 1) {
      statement += ", ";
    }
  }
  statement += ")";
  return statement;
}
}
}
