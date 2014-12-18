/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <map>
#include <memory>
#include <vector>

#include <boost/lexical_cast.hpp>

#include <sqlite3.h>

#include <osquery/database/results.h>
#include <osquery/status.h>

namespace osquery {
namespace tables {

/**
 * @brief The SQLite type affinities are available as macros
 *
 * Type affinities: TEXT, INTEGER, BIGINT
 *
 * You can represent any data that can be lexically casted to a string.
 * Using the type affinity names helps table developers understand the data
 * types they are storing, and more importantly how they are treated at query
 * time.
 */
#define TEXT(x) boost::lexical_cast<std::string>(x)
/// See the affinity type documentation for TEXT.
#define INTEGER(x) boost::lexical_cast<std::string>(x)
/// See the affinity type documentation for TEXT.
#define BIGINT(x) boost::lexical_cast<std::string>(x)
/// See the affinity type documentation for TEXT.
#define UNSIGNED_BIGINT(x) boost::lexical_cast<std::string>(x)

/**
 * @brief The SQLite type affinities as represented as implementation literals.
 *
 * Type affinities: TEXT=std::string, INTEGER=int, BIGINT=long long int
 *
 * Just as the SQLite data is represented as lexically casted strings, as table
 * may make use of the implementation language literals.
 */
#define TEXT_LITERAL std::string
/// See the literal type documentation for TEXT_LITERAL.
#define INTEGER_LITERAL int
/// See the literal type documentation for TEXT_LITERAL.
#define BIGINT_LITERAL long long int
/// See the literal type documentation for TEXT_LITERAL.
#define UNSIGNED_BIGINT_LITERAL unsigned long long int
/// Cast an SQLite affinity type to the literal type.
#define AS_LITERAL(literal, value) boost::lexical_cast<literal>(value)

/**
 * @brief A ConstraintOperator is applied in an query predicate.
 *
 * If the query contains a join or where clause with a constraint operator and
 * expression the table generator may limit the data appropriately.
 */
enum ConstraintOperator {
  EQUALS = 2,
  GREATER_THAN = 4,
  LESS_THAN_OR_EQUALS = 8,
  LESS_THAN = 16,
  GREATER_THAN_OR_EQUALS = 32
};

/**
 * @brief A Constraint is an operator and expression.
 *
 * The constraint is applied to columns which have literal and affinity types.
 */
struct Constraint {
  unsigned char op;
  std::string expr;

  /// Construct a Constraint with the most-basic information, the operator.
  Constraint(unsigned char _op) { op = _op; }
};

/**
 * @brief A ConstraintList is a set of constraints for a column. This list
 * should be mapped to a left-hand-side column name.
 *
 * The table generator does not need to check each constraint in its decision
 * logic. The common constraint checking patterns (match) are abstracted using
 * simple logic operators on the literal SQLite affinity types.
 *
 * A constraint list supports all AS_LITERAL types, and all ConstraintOperators.
 */
struct ConstraintList {
  /// List of constraint operator/expressions.
  std::vector<struct Constraint> constraints;
  /// The SQLite affinity type.
  std::string affinity;

  /**
   * @brief Check if an expression matches the query constraints.
   *
   * @param expr a TEXT representation of the column literal type to check.
   * @return If the expression matched all constraints.
   */
  bool matches(const std::string& expr);

  template <typename T>
  bool matches(const T& expr) {
    return literal_matches<T>(expr);
  }

  /**
   * @brief If there is a constraint on this column.
   */
  bool exists() { return (constraints.size() > 0); }
  bool existsAndMatches(const std::string& expr) {
    return (exists() && matches(expr));
  }

  bool notExistsOrMatches(const std::string& expr) {
    return (!exists() || matches(expr));
  }

  template <typename T>
  bool existsAndMatches(const T& expr);

  template <typename T>
  bool notExistsOrMatches(const T& expr);

  /**
   * @brief Helper templated function for ConstraintList::matches
   */
  template <typename T>
  bool literal_matches(const T& base_expr);

  /**
   * @brief Get all expressions for a given ConstraintOperator.
   *
   * This is most useful if the table generation requires as column.
   * The generator may `getAll(EQUALS)` then iterate.
   *
   * @param op the ConstraintOperator.
   * @return A list of TEXT%-represented types matching the operator.
   */
  std::vector<std::string> getAll(ConstraintOperator op);

  /**
   * @brief Add a new Constraint to the list of constraints.
   *
   * @param constraint a new operator/expression to constrain.
   */
  void add(const struct Constraint& constraint) {
    constraints.push_back(constraint);
  }
};

/// Pass a constraint map to the query request.
typedef std::map<std::string, struct ConstraintList> ConstraintMap;
/// Populate a containst list from a query's parsed predicate.
typedef std::vector<std::pair<std::string, struct Constraint> > ConstraintSet;

/**
 * @brief A QueryContext is provided to every table generator for optimization
 * on query components like predicate constraints and limits.
 */
struct QueryContext {
  ConstraintMap constraints;
  /// Support a limit to the number of results.
  int limit;
};

typedef struct QueryContext QueryContext;
typedef struct Constraint Constraint;
}
}
