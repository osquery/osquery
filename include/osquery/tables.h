/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <deque>
#include <map>
#include <memory>
#include <vector>
#include <set>

#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/registry.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/status.h>

/// Allow Tables to use "tracked" deprecated OS APIs.
#define OSQUERY_USE_DEPRECATED(expr)                                      \
  do {                                                                    \
    _Pragma("clang diagnostic push")                                      \
        _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
        expr;                                                             \
    _Pragma("clang diagnostic pop")                                       \
  } while (0)

namespace osquery {

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
/// See the affinity type documentation for TEXT.
#define DOUBLE(x) boost::lexical_cast<std::string>(x)

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
/// See the literal type documentation for TEXT_LITERAL.
#define DOUBLE_LITERAL double
/// Cast an SQLite affinity type to the literal type.
#define AS_LITERAL(literal, value) boost::lexical_cast<literal>(value)

enum ColumnType {
  UNKNOWN_TYPE = 0,
  TEXT_TYPE,
  INTEGER_TYPE,
  BIGINT_TYPE,
  UNSIGNED_BIGINT_TYPE,
  DOUBLE_TYPE,
  BLOB_TYPE,
};

/// Map of type constant to the SQLite string-name representation.
extern const std::map<ColumnType, std::string> kColumnTypeNames;

/// Helper alias for TablePlugin names.
typedef std::string TableName;
typedef std::vector<std::pair<std::string, ColumnType> > TableColumns;
struct QueryContext;

/**
 * @brief A ConstraintOperator is applied in an query predicate.
 *
 * If the query contains a join or where clause with a constraint operator and
 * expression the table generator may limit the data appropriately.
 */
enum ConstraintOperator : unsigned char {
  EQUALS = 2,
  GREATER_THAN = 4,
  LESS_THAN_OR_EQUALS = 8,
  LESS_THAN = 16,
  GREATER_THAN_OR_EQUALS = 32
};

/// Type for flags for what constraint operators are admissible.
typedef unsigned char ConstraintOperatorFlag;
/// Flag for any operator type.
#define ANY_OP 0xFFU

/**
 * @brief A Constraint is an operator and expression.
 *
 * The constraint is applied to columns which have literal and affinity types.
 */
struct Constraint {
  unsigned char op;
  std::string expr;

  /// Construct a Constraint with the most-basic information, the operator.
  explicit Constraint(unsigned char _op) { op = _op; }

  // A constraint list in a context knows only the operator at creation.
  explicit Constraint(unsigned char _op, const std::string& _expr)
      : op(_op), expr(_expr) {}
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
  /// The SQLite affinity type.
  ColumnType affinity;

  /**
   * @brief Check if an expression matches the query constraints.
   *
   * Evaluate ALL constraints in this ConstraintList against the string
   * expression. The affinity of the constraint will be used as the affinite
   * and lexical type of the expression and set of constraint expressions.
   * If there are no predicate constraints in this list, all expression will
   * match. Constraints are limitations.
   *
   * @param expr a SQL type expression of the column literal type to check.
   * @return If the expression matched all constraints.
   */
  bool matches(const std::string& expr) const;

  /**
   * @brief Check if an expression matches the query constraints.
   *
   * `matches` also supports the set of SQL affinite types.
   * The expression expr will be evaluated as a string and compared using
   * the affinity of the constraint.
   *
   * @param expr a SQL type expression of the column literal type to check.
   * @return If the expression matched all constraints.
   */
  template <typename T>
  bool matches(const T& expr) const {
    return matches(TEXT(expr));
  }

  /**
   * @brief Check and return if there are constraints on this column.
   *
   * A ConstraintList is used in a ConstraintMap with a column name as the
   * map index. Tables that act on optional constraints should check if any
   * constraint was provided.  The ops parameter serves to specify which
   * operators we want to check existence for.
   *
   * @param ops (Optional: default ANY_OP) The operators types to look for.
   * @return true if any constraint exists.
   */
  bool exists(const ConstraintOperatorFlag ops = ANY_OP) const;

  /**
   * @brief Check if a constraint exists AND matches the type expression.
   *
   * See ConstraintList::exists and ConstraintList::matches.
   *
   * @param expr The expression to match.
   * @return true if any constraint exists AND matches the type expression.
   */
  template <typename T>
  bool existsAndMatches(const T& expr) const {
    return (exists() && matches(expr));
  }

  /**
   * @brief Check if a constraint is missing or matches a type expression.
   *
   * A ConstraintList is used in a ConstraintMap with a column name as the
   * map index. Tables that act on required constraints can make decisions
   * on missing constraints or a constraint match.
   *
   * @param expr The expression to match.
   * @return true if constraint is missing or matches the type expression.
   */
  template <typename T>
  bool notExistsOrMatches(const T& expr) const {
    return (!exists() || matches(expr));
  }

  /**
   * @brief Helper templated function for ConstraintList::matches.
   */
  template <typename T>
  bool literal_matches(const T& base_expr) const;

  /**
   * @brief Get all expressions for a given ConstraintOperator.
   *
   * This is most useful if the table generation requires as column.
   * The generator may `getAll(EQUALS)` then iterate.
   *
   * @param op the ConstraintOperator.
   * @return A list of TEXT%-represented types matching the operator.
   */
  std::set<std::string> getAll(ConstraintOperator op) const;

  /// See ConstraintList::getAll, but as a selected literal type.
  template <typename T>
  std::set<T> getAll(ConstraintOperator op) const {
    std::set<T> literal_matches;
    auto matches = getAll(op);
    for (const auto& match : matches) {
      literal_matches.insert(AS_LITERAL(T, match));
    }
    return literal_matches;
  }

  /// Constraint list accessor, types and operator.
  const std::vector<struct Constraint>& getAll() const { return constraints_; }

  /**
   * @brief Add a new Constraint to the list of constraints.
   *
   * @param constraint a new operator/expression to constrain.
   */
  void add(const struct Constraint& constraint) {
    constraints_.push_back(constraint);
  }

  /**
   * @brief Serialize a ConstraintList into a property tree.
   *
   * The property tree will use the format:
   * {
   *   "affinity": affinity,
   *   "list": [
   *     {"op": op, "expr": expr}, ...
   *   ]
   * }
   */
  void serialize(boost::property_tree::ptree& tree) const;

  /// See ConstraintList::unserialize.
  void unserialize(const boost::property_tree::ptree& tree);

  ConstraintList() : affinity(TEXT_TYPE) {}

 private:
  /// List of constraint operator/expressions.
  std::vector<struct Constraint> constraints_;

 private:
  friend struct QueryContext;

 private:
  FRIEND_TEST(TablesTests, test_constraint_list);
};

/// Pass a constraint map to the query request.
typedef std::map<std::string, struct ConstraintList> ConstraintMap;
/// Populate a constraint list from a query's parsed predicate.
typedef std::vector<std::pair<std::string, struct Constraint> > ConstraintSet;

/**
 * @brief A QueryContext is provided to every table generator for optimization
 * on query components like predicate constraints and limits.
 */
struct QueryContext {
  /**
   * @brief Check if a constraint exists for a given column operator pair.
   *
   * Operator and expression existence and matching occurs on the constraint
   * list for a given column name. The query context maintains a map of columns
   * to potentially empty constraint lists. Check if a constraint exists with
   * any operator or for a specific operator, usually equality (EQUALS).
   *
   * @param column The name of a column within this table.
   * @param optional op Check for a specific constraint operator.
   * @return true if a constraint exists, false if empty or no operator match.
   */
  bool hasConstraint(const std::string& column,
                     ConstraintOperator op = EQUALS) const;

  /**
   * @brief Apply a predicate function to each expression in a constraint list.
   *
   * Most constraint sets are use to extract expressions or perform a row
   * generation for each expressions (given an operator).
   *
   * This prevents the caller (table implementation) from extracting the set
   * and iterating separately on potentially duplicate and copied data. The
   * predicate function is provided two arguments:
   *  - An iterating reference to each expression for the given operator.
   *
   * @param column The name of a column within this table.
   * @param op The comparison or expression operator (e.g., EQUALS).
   * @param predicate A predicate receiving each expression.
   */
  template <typename T>
  void forEachConstraint(const std::string& column,
                         ConstraintOperator op,
                         std::function<void(const T& expr)> predicate) const {
    if (constraints.count(column) > 0) {
      const auto& list = constraints.at(column);
      if (list.affinity == TEXT_TYPE) {
        for (const auto& constraint : list.constraints_) {
          if (constraint.op == op) {
            predicate(constraint.expr);
          }
        }
      } else {
        auto constraint_set = list.getAll<T>(op);
        for (const auto& constraint : constraint_set) {
          predicate(constraint);
        }
      }
    }
  }

  void forEachConstraint(
      const std::string& column,
      ConstraintOperator op,
      std::function<void(const std::string& expr)> predicate) const {
    return forEachConstraint<std::string>(column, op, predicate);
  }

  ConstraintMap constraints;
  /// Support a limit to the number of results.
  int limit{0};
  /// Is the table allowed to "traverse" directories.
  bool traverse{false};
};

typedef struct QueryContext QueryContext;
typedef struct Constraint Constraint;

/**
 * @brief The TablePlugin defines the name, types, and column information.
 *
 * To attach a virtual table create a TablePlugin subclass and register the
 * virtual table name as the plugin ID. osquery will enumerate all registered
 * TablePlugins and attempt to attach them to SQLite at instantiation.
 *
 * Note: When updating this class, be sure to update the corresponding template
 * in osquery/tables/templates/default.cpp.in
 */
class TablePlugin : public Plugin {
 protected:
  /// Return the table's column name and type pairs.
  virtual TableColumns columns() const { return TableColumns(); }

  /**
   * @brief Generate a complete table representation.
   *
   * The TablePlugin::generate method is the most important part of the table.
   * This should return a best-effort match of the expected results for a
   * query. In common cases, this returns all rows for a virtual table.
   * For EventSubscriber tables this will perform database lookups for events
   * matching several conditions such as time within the SQL query or the last
   * time the EventSubscriber was called.
   *
   * The context input is filled in "as best possible" by SQLite's
   * virtual table APIs. In the best case this context include a limit or
   * constraints organized by each possible column.
   *
   * @param request A query context filled in by SQLite's virtual table API.
   * @return The result rows for this table, given the query context.
   */
  virtual QueryData generate(QueryContext& request) { return QueryData(); }

 protected:
  /// An SQL table containing the table definition/syntax.
  std::string columnDefinition() const;

  /// Return the name and column pairs for attaching virtual tables.
  PluginResponse routeInfo() const override;

  /**
   * @brief Check if there are fresh cache results for this table.
   *
   * Table results are considered fresh when evaluated against a given interval.
   * The interval is the expected rate for which this data should be generated.
   * Caching and cache freshness only applies to queries acting on tables
   * within a schedule. If two queries "one" and "two" both inspect the
   * table "processes" at the interval 60. The first executed will cache results
   * and the second will use the cached results.
   *
   * Table results are not cached if a QueryContext contains constraints or
   * provides HOB (hand-off blocks) to additional tables within a query.
   * Currently, the query scheduler cannot communicate to table implementations.
   * An interval is set globally by the scheduler and passed to the table
   * implementation as a future-proof API. There is no "shortcut" for caching
   * when used in external tables. A cache lookup within an extension means
   * a database call API and re-serialization to the virtual table APIs. In
   * practice this does not perform well and is explicitly disabled.
   *
   * @param interval The interval this query expects the tables results.
   * @return True if the cache contains fresh results, otherwise false.
   */
  bool isCached(size_t interval);

  /**
   * @brief Perform a database lookup of cached results and deserialize.
   *
   * If a query determined the table's cached results are fresh, it may ask the
   * table to retrieve results from the database and deserialized them into
   * table row data.
   *
   * @return The deserialized row data of cached results.
   */
  QueryData getCache() const;

  /// Similar to TablePlugin::getCache, if TablePlugin::generate is called.
  void setCache(size_t step, size_t interval, const QueryData& results);

 private:
  /// The last time in seconds the table data results were saved to cache.
  size_t last_cached_{0};
  /// The last interval in seconds when the table data was cached.
  size_t last_interval_{0};

 public:
  /**
   * @brief The scheduled interval for the executing query.
   *
   * Scheduled queries execute within a pseudo-mutex, and each may communicate
   * their scheduled interval to internal TablePlugin implementations. If the
   * table is cachable then the interval can be used to calculate freshness.
   */
  static size_t kCacheInterval;
  /// The schedule step, this is the current position of the schedule.
  static size_t kCacheStep;

 public:
  /**
   * @brief The registry call "router".
   *
   * Like all of osquery's Plugin%s, the TablePlugin uses a "call" router to
   * handle requests and responses from extensions. The TablePlugin uses an
   * "action" key, which can be:
   *   - generate: call the plugin's row generate method (defined in spec).
   *   - columns: return a list of column name and SQLite types.
   *   - definition: return an SQL statement for table creation.
   *
   * @param request The plugin request, must include an action key.
   * @param response A plugin response, for generation this contains the rows.
   */
  Status call(const PluginRequest& request, PluginResponse& response) override;

 public:
  /// Helper data structure transformation methods.
  static void setRequestFromContext(const QueryContext& context,
                                    PluginRequest& request);

  /// Helper data structure transformation methods.
  static void setContextFromRequest(const PluginRequest& request,
                                    QueryContext& context);

 public:
  /**
   * @brief Add a virtual table that exists in an extension.
   *
   * When external table plugins are registered the core will attach them
   * as virtual tables to the SQL internal implementation.
   *
   * @param name The table name.
   * @param info The route info (column name and type pairs).
   */
  static Status addExternal(const std::string& name,
                            const PluginResponse& info);

  /// Remove an extension's table from the SQL virtual database.
  static void removeExternal(const std::string& name);

 private:
  FRIEND_TEST(VirtualTableTests, test_tableplugin_columndefinition);
  FRIEND_TEST(VirtualTableTests, test_tableplugin_statement);
};

/// Helper method to generate the virtual table CREATE statement.
std::string columnDefinition(const TableColumns& columns);

/// Helper method to generate the virtual table CREATE statement.
std::string columnDefinition(const PluginResponse& response);

/// Get the string representation for an SQLite column type.
inline const std::string& columnTypeName(ColumnType type) {
  return kColumnTypeNames.at(type);
}

/// Get the column type from the string representation.
ColumnType columnTypeName(const std::string& type);

CREATE_LAZY_REGISTRY(TablePlugin, "table");
}
