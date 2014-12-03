// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/logger.h"
#include "osquery/tables.h"

namespace osquery {
namespace tables {

bool ConstraintList::matches(const std::string& expr) {
  // Support each affinity type casting.
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
  for (size_t i = 0; i < constraints.size(); ++i) {
    T constraint_expr = AS_LITERAL(T, constraints[i].expr);
    if (constraints[i].op == EQUALS) {
      aggregate = aggregate && (base_expr == constraint_expr);
    } else if (constraints[i].op == GREATER_THAN) {
      aggregate = aggregate && (base_expr > constraint_expr);
    } else if (constraints[i].op == LESS_THAN) {
      aggregate = aggregate && (base_expr < constraint_expr);
    } else if (constraints[i].op == GREATER_THAN_OR_EQUALS) {
      aggregate = aggregate && (base_expr >= constraint_expr);
    } else if (constraints[i].op == LESS_THAN_OR_EQUALS) {
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
  for (size_t i = 0; i < constraints.size(); ++i) {
    if (constraints[i].op == op) {
      // TODO: this does not apply a distinct.
      set.push_back(constraints[i].expr);
    }
  }
  return set;
}

template <typename T>
bool ConstraintList::existsAndMatches(const T& expr) {
  return (exists() && literal_matches<T>(expr));
}

template <typename T>
bool ConstraintList::notExistsOrMatches(const T& expr) {
  return (!exists() || literal_matches<T>(expr));
}
}
}
