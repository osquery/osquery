// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <map>
#include <vector>

#include <boost/lexical_cast.hpp>

#include "osquery/database/results.h"
#include "osquery/status.h"

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
#define INTEGER(x) boost::lexical_cast<std::string>(x)
#define BIGINT(x) boost::lexical_cast<std::string>(x)
#define UNSIGNED_BIGINT(x) boost::lexical_cast<std::string>(x)

/// Literal types are the C++ types.
#define TEXT_LITERAL std::string
#define INTEGER_LITERAL int
#define BIGINT_LITERAL long long int
#define UNSIGNED_BIGINT_LITERAL unsigned long long int
#define AS_LITERAL(literal, value) boost::lexical_cast<literal>(value)

enum ConstraintOperators {
  EQUALS = 2,
  GREATER_THAN = 4,
  LESS_THAN_OR_EQUALS = 8,
  LESS_THAN = 16,
  GREATER_THAN_OR_EQUALS = 32
};

struct Constraint {
  unsigned char op;
  std::string expr;

  Constraint(unsigned char _op) { op = _op; }
};

struct ConstraintList {
  std::vector<struct Constraint> constraints;
  /// The SQLite affinity type.
  std::string affinity;

  bool matches(const std::string& expr) {
    // Support each affinity type casting.
    if (affinity == "TEXT") {
      return literal_matches<TEXT_LITERAL>(expr); 
    } else if (affinity == "INTEGER") {
      return literal_matches<INTEGER_LITERAL>(expr);
    } else if (affinity == "BIGINT") {
      return literal_matches<BIGINT_LITERAL>(expr);
    } else if (affinity == "UNSIGNED_BIGINT") {
      return literal_matches<UNSIGNED_BIGINT_LITERAL>(expr);
    } else {
      // Unsupprted affinity type.
      return false;
    }
  }

  template <typename T>
  bool literal_matches(const std::string& base_expr) {
    bool aggregate = true;
    T expr = AS_LITERAL(T, base_expr);
    for (size_t i = 0; i < constraints.size(); ++i) {
      T constraint_expr = AS_LITERAL(T, constraints[i].expr);
      if (constraints[i].op == EQUALS) {
        aggregate = aggregate && (expr == constraint_expr);
      } else if (constraints[i].op == GREATER_THAN) {
        aggregate = aggregate && (expr > constraint_expr);
      } else if (constraints[i].op == LESS_THAN) {
        aggregate = aggregate && (expr < constraint_expr);
      } else if (constraints[i].op == GREATER_THAN_OR_EQUALS) {
        aggregate = aggregate && (expr >= constraint_expr);
      } else if (constraints[i].op == LESS_THAN_OR_EQUALS) {
        aggregate = aggregate && (expr <= constraint_expr);
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

  std::vector<std::string> getAll(ConstraintOperators op) {
    std::vector<std::string> set;
    for (size_t i = 0; i < constraints.size(); ++i) {
      if (constraints[i].op == op) {
        set.push_back(constraints[i].expr);
      }
    }
    return set;
  }

  void add(const struct Constraint& constraint) {
    constraints.push_back(constraint);
  }
};

/// Pass a constraint map to the query request.
typedef std::map<std::string, struct ConstraintList> ConstraintMap;
/// Populate a containst list from a query's parsed predicate.
typedef std::vector<std::pair<std::string, struct Constraint> > ConstraintSet;

struct QueryRequest {
  ConstraintMap constraints;
  /// Support a limit to the number of results.
  int limit;
};

typedef struct QueryRequest QueryRequest;
typedef struct Constraint Constraint;

}
}