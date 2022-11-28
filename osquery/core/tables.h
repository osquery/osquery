/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <bitset>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/core/ignore_unused.hpp>
#include <boost/coroutine2/coroutine.hpp>
#include <boost/optional.hpp>
#include <sqlite3.h>

#include <osquery/core/core.h>
#include <osquery/core/plugins/plugin.h>
#include <osquery/core/query.h>
#include <osquery/core/sql/column.h>

#include <gtest/gtest_prod.h>

/// Allow Tables to use "tracked" deprecated OS APIs.
#define OSQUERY_USE_DEPRECATED(expr)                                           \
  do {                                                                         \
    _Pragma("clang diagnostic push") _Pragma(                                  \
        "clang diagnostic ignored \"-Wdeprecated-declarations\"")(expr);       \
    _Pragma("clang diagnostic pop")                                            \
  } while (0)

namespace osquery {

class Status;
/**
 * @brief osquery does not yet use a NULL type.
 *
 * If a column type is non-TEXT a NULL is defined as an empty result. The APIs
 * may later define an explicit control set that is opaque to the table
 * implementation.
 */
#define SQL_NULL_RESULT ""

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
template <typename Type>
inline std::string __sqliteField(const Type& source) noexcept {
  return std::to_string(source);
}

template <size_t N>
inline std::string __sqliteField(const char (&source)[N]) noexcept {
  return std::string(source, N - 1U);
}

template <size_t N>
inline std::string __sqliteField(const unsigned char (&source)[N]) noexcept {
  return std::string(reinterpret_cast<const char*>(source), N - 1U);
}

inline std::string __sqliteField(const char* source) noexcept {
  return std::string(source);
}

inline std::string __sqliteField(char* const source) noexcept {
  return std::string(source);
}

inline std::string __sqliteField(const unsigned char* source) noexcept {
  return std::string(reinterpret_cast<const char*>(source));
}

inline std::string __sqliteField(unsigned char* const source) noexcept {
  return std::string(reinterpret_cast<char* const>(source));
}

inline std::string __sqliteField(const std::string& source) noexcept {
  return source;
}

#ifdef WIN32
// TEXT is also defined in windows.h, we should not re-define it
#define SQL_TEXT(x) __sqliteField(x)
#else
#define SQL_TEXT(x) __sqliteField(x)
#define TEXT(x) __sqliteField(x)
#endif

/// See the affinity type documentation for TEXT.
#define INTEGER(x) __sqliteField(x)
/// See the affinity type documentation for TEXT.
#define BIGINT(x) __sqliteField(x)
/// See the affinity type documentation for TEXT.
#define UNSIGNED_BIGINT(x) __sqliteField(x)
/// See the affinity type documentation for TEXT.
#define DOUBLE(x) __sqliteField(x)

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
#define BIGINT_LITERAL int64_t
/// See the literal type documentation for TEXT_LITERAL.
#define UNSIGNED_BIGINT_LITERAL uint64_t
/// See the literal type documentation for TEXT_LITERAL.
#define DOUBLE_LITERAL double

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
  GREATER_THAN_OR_EQUALS = 32,
  MATCH = 64,
  LIKE = 65,
  GLOB = 66,
  REGEXP = 67,
  UNIQUE = 1,
};

/// Type for flags for what constraint operators are admissible.
using ConstraintOperatorFlag = unsigned char;

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
  explicit Constraint(unsigned char _op) {
    op = _op;
  }

  // A constraint list in a context knows only the operator at creation.
  explicit Constraint(unsigned char _op, std::string _expr)
      : op(_op), expr(std::move(_expr)) {}
};

/**
 * @brief Attributes about a Table implementation.
 */
enum class TableAttributes {
  /// Default no-op attribute.
  NONE = 0,

  /// This table is a 'utility' and is always available locally.
  UTILITY = 1,

  /// The results from this table may be cached within a schedule.
  CACHEABLE = 2,

  /// The results are backed by a set time-indexed, always growing, events.
  EVENT_BASED = 4,

  /// This table inspect items relative to each user, a JOIN may be required.
  USER_BASED = 8,

  /// (Deprecated) This table's data requires an osquery kernel module.
  KERNEL_REQUIRED = 16,
};

/// Treat table attributes as a set of flags.
inline TableAttributes operator|(TableAttributes a, TableAttributes b) {
  return static_cast<TableAttributes>(static_cast<int>(a) |
                                      static_cast<int>(b));
}

/// Treat column options as a set of flags.
inline size_t operator&(TableAttributes a, TableAttributes b) {
  return static_cast<size_t>(a) & static_cast<size_t>(b);
}

/// Alias for an ordered list of column name and corresponding SQL type.
using TableColumns =
    std::vector<std::tuple<std::string, ColumnType, ColumnOptions>>;

/// Alias for map of column alias sets.
using ColumnAliasSet = std::map<std::string, std::set<std::string>>;

/// Alias for a map of alias to canonical column names
using AliasColumnMap = std::unordered_map<std::string, std::string>;

/// Forward declaration of QueryContext for ConstraintList relationships.
struct QueryContext;

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
struct ConstraintList : private boost::noncopyable {
 public:
  /// The SQLite affinity type.
  ColumnType affinity{TEXT_TYPE};

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
    return matches(SQL_TEXT(expr));
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
  bool exists(ConstraintOperatorFlag ops = ANY_OP) const;

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
  std::set<T> getAll(ConstraintOperator op) const;

  /// Constraint list accessor, types and operator.
  const std::vector<struct Constraint>& getAll() const {
    return constraints_;
  }

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
  void serialize(JSON& doc, rapidjson::Value& obj) const;

  /// See ConstraintList::unserialize.
  void deserialize(const rapidjson::Value& obj);

 private:
  /// List of constraint operator/expressions.
  std::vector<struct Constraint> constraints_;

 private:
  friend struct QueryContext;

 private:
  FRIEND_TEST(TablesTests, test_constraint_list);
};

/// Pass a constraint map to the query request.
using ConstraintMap = std::map<std::string, struct ConstraintList>;

/// Populate a constraint list from a query's parsed predicate.
using ConstraintSet = std::vector<std::pair<std::string, struct Constraint>>;

/// Keep track of which columns are used
using UsedColumns = std::unordered_set<std::string>;

/// Keep track of which columns are used, as a bitset
using UsedColumnsBitset = std::bitset<
    std::numeric_limits<decltype(sqlite3_index_info().colUsed)>::digits>;

/**
 * @brief osquery table content descriptor.
 *
 * This object is the abstracted SQLite database's virtual table descriptor.
 * When the virtual table is created/connected the name and columns are
 * retrieved via the TablePlugin call API. The details are kept in this context
 * so column parsing and row walking does not require additional Registry calls.
 *
 * When tables are accessed as the result of an SQL statement a QueryContext is
 * created to represent metadata that can be used by the virtual table
 * implementation code. Thus the code that generates rows can choose to emit
 * additional data, restrict based on constraints, or potentially yield from
 * a cache or choose not to generate certain columns.
 */
struct VirtualTableContent {
  /// Friendly name for the table.
  TableName name;

  /// Table column structure, retrieved once via the TablePlugin call API.
  TableColumns columns;

  /// Attributes are copied into the content such that they can be quickly
  /// passed to the SQL and optional Query for inspection.
  TableAttributes attributes{TableAttributes::NONE};

  /**
   * @brief Table column aliases structure.
   *
   * This is used within xColumn to move content from special HIDDEN columns
   * that act as aliases. If these columns are requested the content is moved
   * from the new non-deprecated name.
   */
  std::map<std::string, size_t> aliases;

  /// Transient set of virtual table access constraints.
  std::unordered_map<size_t, ConstraintSet> constraints;

  /// Transient set of virtual table used columns
  std::unordered_map<size_t, UsedColumns> colsUsed;

  /// Transient set of virtual table used columns (as bitmasks)
  std::unordered_map<size_t, UsedColumnsBitset> colsUsedBitsets;

  /*
   * @brief A table implementation specific query result cache.
   *
   * Virtual tables may 'cache' information between filter requests. This is
   * intended to provide optimization for very latent/expensive tables where
   * complex joins may result in duplicate filter requests.
   *
   * The cache is implemented as a map of row data. The cache concept
   * should utilize a primary key as an index, and may store arbitrary data.
   * More intense caching may use the backing store though the general database
   * set and get calls.
   *
   * The in-memory, non-backing store, cache is expired after each query run.
   * This caching does not affect or use the schedule results cache.
   */
  std::map<std::string, TableRowHolder> cache;
};

using RowGenerator = boost::coroutines2::coroutine<TableRowHolder>;
using RowYield = RowGenerator::push_type;

/**
 * @brief A QueryContext is provided to every table generator for optimization
 * on query components like predicate constraints and limits.
 */
struct QueryContext {
  /// Construct a context without cache support.
  QueryContext() {
    table_ = std::make_shared<VirtualTableContent>();
  }

  /// If the context was created without content, it is ephemeral.
  ~QueryContext() = default;

  /// Construct a context and set the table content for caching.
  explicit QueryContext(std::shared_ptr<VirtualTableContent> content)
      : enable_cache_(true), table_(std::move(content)) {}

  /// Disallow copying
  QueryContext(const QueryContext&) = delete;

  /// Disallow copy assignment.
  QueryContext& operator=(const QueryContext&) = delete;

  /// Allow moving.
  QueryContext(QueryContext&& other)
      : constraints(std::move(other.constraints)),
        colsUsed(std::move(other.colsUsed)),
        enable_cache_(other.enable_cache_),
        use_cache_(other.use_cache_),
        table_(other.table_) {
    other.enable_cache_ = false;
    other.table_ = nullptr;
  }

  /// Allow move assignment.
  QueryContext& operator=(QueryContext&& other) {
    std::swap(constraints, other.constraints);
    std::swap(colsUsed, other.colsUsed);
    std::swap(enable_cache_, other.enable_cache_);
    std::swap(use_cache_, other.use_cache_);
    std::swap(table_, other.table_);

    return *this;
  }

  /**
   * @brief Check if a constraint exists for a given column operator pair.
   *
   * Operator and expression existence and matching occurs on the constraint
   * list for a given column name. The query context maintains a map of columns
   * to potentially empty constraint lists. Check if a constraint exists with
   * any operator or for a specific operator, usually equality (EQUALS).
   *
   * @param column The name of a column within this table.
   * @param op Check for a specific constraint operator (default EQUALS).
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
  void iteritems(const std::string& column,
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

  /// Helper for string type (most all types are TEXT/VARCHAR).
  void iteritems(const std::string& column,
                 ConstraintOperator op,
                 std::function<void(const std::string& expr)> predicate) const {
    return iteritems<std::string>(column, op, std::move(predicate));
  }

  /**
   * @brief Expand a list of constraints into a set of values.
   *
   * This is most (perhaps only) helpful with filesystem globbing inputs.
   * The requirement is a constraint column that takes an expandable input.
   * This method will accept an expand predicate and return the aggregate set of
   * expanded items.
   *
   * In the future this will be a templated type that restricts the predicate
   * to act on the column's affinite type and returns a similar-typed set.
   *
   * @param column The name of a column within this table.
   * @param op An operator to retrieve from the constraint list.
   * @param output The output parameter, a set of expanded values.
   * @param predicate A predicate lambda to apply to each constraint.
   * @return An aggregate status, if any predicate fails the operation fails.
   */
  Status expandConstraints(
      const std::string& column,
      ConstraintOperator op,
      std::set<std::string>& output,
      std::function<Status(const std::string& constraint,
                           std::set<std::string>& output)> predicate);

  /// Check if the given column is used by the query
  bool isColumnUsed(const std::string& colName) const;

  /// Check if any of the given columns is used by the query
  bool isAnyColumnUsed(std::initializer_list<std::string> colNames) const;

  /// Check if this is a star-select or similar.
  bool defaultColumnsUsed() const;

  inline bool isAnyColumnUsed(UsedColumnsBitset desiredBitset) const {
    return !colsUsedBitset || (*colsUsedBitset & desiredBitset).any();
  }

  template <typename Type>
  inline void setTextColumnIfUsed(Row& r,
                                  const std::string& colName,
                                  const Type& value) const {
    if (isColumnUsed(colName)) {
      r[colName] = TEXT(value);
    }
  }

  template <typename Type>
  inline void setIntegerColumnIfUsed(Row& r,
                                     const std::string& colName,
                                     const Type& value) const {
    if (isColumnUsed(colName)) {
      r[colName] = INTEGER(value);
    }
  }

  template <typename Type>
  inline void setBigIntColumnIfUsed(Row& r,
                                    const std::string& colName,
                                    const Type& value) const {
    if (isColumnUsed(colName)) {
      r[colName] = BIGINT(value);
    }
  }

  inline void setColumnIfUsed(Row& r,
                              const std::string& colName,
                              const std::string& value) const {
    if (isColumnUsed(colName)) {
      r[colName] = value;
    }
  }

  /// Check if a table-defined index exists within the query cache.
  bool isCached(const std::string& index) const;

  /// Retrieve an index within the query cache.
  TableRowHolder getCache(const std::string& index);

  /// Request the context use the warm query cache.
  void useCache(bool use_cache);

  /// Check if the query requested use of the warm query cache.
  bool useCache() const;

  /// Set the entire cache for an index.
  void setCache(const std::string& index, const TableRowHolder& _cache);

  /// The map of column name to constraint list.
  ConstraintMap constraints;

  boost::optional<UsedColumns> colsUsed;
  boost::optional<UsedColumnsBitset> colsUsedBitset;

 private:
  /// If false then the context is maintaining an ephemeral cache.
  bool enable_cache_{false};

  /// If the context is allowed to use the warm query cache.
  bool use_cache_{false};

  /// Persistent table content for table caching.
  std::shared_ptr<VirtualTableContent> table_;

 private:
  friend class TablePlugin;
};

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
 public:
  /**
   * @brief Table name aliases create full-scan VIEWs for tables.
   *
   * Aliases allow table names to be changed/deprecated without breaking
   * existing deployments and scheduled queries.
   *
   * @return A string vector of qtable name aliases.
   */
  virtual std::vector<std::string> aliases() const {
    return {};
  }

  /// Return the table's column name and type pairs.
  virtual TableColumns columns() const {
    return TableColumns();
  }

  /// Define a map of target columns to optional aliases.
  virtual ColumnAliasSet columnAliases() const {
    return ColumnAliasSet();
  }

  /// Define a map of aliases to canonical columns
  virtual AliasColumnMap aliasedColumns() const {
    AliasColumnMap result;

    for (const auto& columnAliases : columnAliases()) {
      const auto& columnName = columnAliases.first;
      for (const auto& alias : columnAliases.second) {
        result[alias] = columnName;
      }
    }

    return AliasColumnMap();
  }

  /// Return a set of attribute flags.
  virtual TableAttributes attributes() const {
    return TableAttributes::NONE;
  }

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
   * @param context A query context filled in by SQLite's virtual table API.
   * @return The result rows for this table, given the query context.
   */
  virtual TableRows generate(QueryContext& context) {
    (void)context;
    return TableRows();
  }

  /// Callback for DELETE statements
  virtual QueryData delete_(QueryContext& context,
                            const PluginRequest& request) {
    boost::ignore_unused(context);
    boost::ignore_unused(request);

    return {{std::make_pair("status", "readonly")}};
  }

  /// Callback for INSERT statements
  virtual QueryData insert(QueryContext& context,
                           const PluginRequest& request) {
    boost::ignore_unused(context);
    boost::ignore_unused(request);

    return {{std::make_pair("status", "readonly")}};
  }

  /// Callback for UPDATE statements
  virtual QueryData update(QueryContext& context,
                           const PluginRequest& request) {
    boost::ignore_unused(context);
    boost::ignore_unused(request);

    return {{std::make_pair("status", "readonly")}};
  }

  /**
   * @brief Generate a table representation by yielding each row.
   *
   * For tables that set generator=True in their spec's implementation, this
   * generator will be bound to an asymmetric coroutine. It should call the
   * provided yield function for each Row returned. Treat this like Python's
   * generator-type methods where the only difference is yield is not reserved
   * but rather provided with some boilerplate syntax.
   *
   * This implementation uses nearly %5 more cycles than the generate method
   * when the table content is small (less than 100 rows) and has a disadvantage
   * of not being cachable since the entire contents are not available before
   * post-filter aggregations. This implementation prevents the need for
   * multiple representations of table content existing simultaneously and is
   * always more memory efficient. It can be more compute efficient for tables
   * with over 1000 rows.
   *
   * @param yield a callable that takes a single Row as input.
   * @param context a query context filled in by SQLite's virtual table API.
   */
  virtual void generator(RowYield& yield, QueryContext& context) {
    (void)yield;
    (void)context;
  }

  /// Override and return true to use the generator and yield method.
  virtual bool usesGenerator() const {
    return false;
  }

 protected:
  /// An SQL table containing the table definition/syntax.
  std::string columnDefinition(bool is_extension = false) const;

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
   * @param ctx The query context.
   * @return True if the cache contains fresh results, otherwise false.
   */
  bool isCached(uint64_t interval, const QueryContext& ctx) const;

  /**
   * @brief Perform a database lookup of cached results and deserialize.
   *
   * If a query determined the table's cached results are fresh, it may ask the
   * table to retrieve results from the database and deserialized them into
   * table row data.
   *
   * @return The deserialized row data of cached results.
   */
  TableRows getCache() const;

  /**
   * @brief Similar to getCache, stores the results from generate.
   *
   * Set will serialize and save the results as JSON to be retrieved later.
   * It will inspect the query context, if any required/indexed/optimized or
   * additional columns are used then the cache will not be saved.
   */
  void setCache(uint64_t step,
                uint64_t interval,
                const QueryContext& ctx,
                const TableRows& results);

 private:
  /// The last time in seconds the table data results were saved to cache.
  uint64_t last_cached_{0};

  /// The last interval in seconds when the table data was cached.
  uint64_t last_interval_{0};

 public:
  /**
   * @brief The scheduled interval for the executing query.
   *
   * Scheduled queries execute within a pseudo-mutex, and each may communicate
   * their scheduled interval to internal TablePlugin implementations. If the
   * table is cachable then the interval can be used to calculate freshness.
   */
  static uint64_t kCacheInterval;

  /// The schedule step, this is the current position of the schedule.
  static uint64_t kCacheStep;

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
  /// Helper data structure transformation methods.
  QueryContext getContextFromRequest(const PluginRequest& request) const;

  UsedColumnsBitset usedColumnsToBitset(const UsedColumns usedColumns) const;
  friend class RegistryFactory;
  FRIEND_TEST(VirtualTableTests, test_tableplugin_columndefinition);
  FRIEND_TEST(VirtualTableTests, test_extension_tableplugin_columndefinition);
  FRIEND_TEST(VirtualTableTests, test_tableplugin_statement);
  FRIEND_TEST(VirtualTableTests, test_indexing_costs);
  FRIEND_TEST(VirtualTableTests, test_table_results_cache);
  FRIEND_TEST(VirtualTableTests, test_table_results_cache_colcheck);
  FRIEND_TEST(VirtualTableTests, test_yield_generator);
};

/// Helper method to generate the virtual table CREATE statement.
std::string columnDefinition(const TableColumns& columns,
                             bool is_extension = false);

/// Helper method to generate the virtual table CREATE statement.
std::string columnDefinition(const PluginResponse& response,
                             bool aliases = false,
                             bool is_extension = false);

/// Get the string representation for an SQLite column type.
inline const std::string& columnTypeName(ColumnType type) {
  return kColumnTypeNames.at(type);
}

/// Get the column type from the string representation.
ColumnType columnTypeName(const std::string& type);

Status deserializeQueryContextJSON(const JSON& json_helper,
                                   QueryContext& context);
void serializeQueryContextJSON(const QueryContext& context, JSON& json_helper);
} // namespace osquery
