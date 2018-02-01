/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <deque>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#ifndef WIN32
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
#endif

/// Wrap this include with the above and below ignored warnings for FreeBSD.
#include <boost/coroutine2/all.hpp>

#ifndef WIN32
#pragma clang diagnostic pop
#endif

#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/core.h>
#include <osquery/query.h>
#include <osquery/registry.h>
#include <osquery/status.h>

/// Allow Tables to use "tracked" deprecated OS APIs.
#define OSQUERY_USE_DEPRECATED(expr)                                           \
  do {                                                                         \
    _Pragma("clang diagnostic push") _Pragma(                                  \
        "clang diagnostic ignored \"-Wdeprecated-declarations\"")(expr);       \
    _Pragma("clang diagnostic pop")                                            \
  } while (0)

namespace osquery {

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
  std::string dest;
  if (!boost::conversion::try_lexical_convert(source, dest)) {
    return SQL_NULL_RESULT;
  }
  return dest;
}

#ifdef WIN32
// TEXT is also defined in windows.h, we should not re-define it
#define SQL_TEXT(x) __sqliteField(x)
#else
// For everything except Windows, aldo define TEXT() to be compatible with
// existing tables
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

/*
 * @brief Column options allow for more-complicated modeling of concepts.
 *
 * To accommodate the oddities of operating system concepts we make use of
 * simple SQLite abstractions like indexs/keys and foreign keys, we also
 * allow for optimizing based on query constraints (WHERE).
 *
 * There are several 'complications' where the default table filter (SELECT)
 * behavior attempts to mimic reality. Browser plugins or shell history are
 * good examples, a SELECT without using a WHERE returns the plugins or
 * history as it applies to the user running the query. If osquery is meant
 * to be a daemon with absolute visibility this introduces an abnormality,
 * as the expected result will only include the superuser's view, even if
 * the superuser can view everything if they intended.
 *
 * The solution is to explicitly ask for everything, by joining against the
 * users table. This options structure will allow the table implementations
 * to communicate these subtleties to the user.
 */
enum class ColumnOptions {
  /// Default/no options.
  DEFAULT = 0,

  /// Treat this column as a primary key.
  INDEX = 1,

  /// This column MUST be included in the query predicate.
  REQUIRED = 2,

  /*
   * @brief This column is used to generate additional information.
   *
   * If this column is included in the query predicate, the table will generate
   * additional information. Consider the browser_plugins or shell history
   * tables: by default they list the plugins or history relative to the user
   * running the query. However, if the calling query specifies a UID explicitly
   * in the predicate, the meaning of the table changes and results for that
   * user are returned instead.
   */
  ADDITIONAL = 4,

  /*
   * @brief This column can be used to optimize the query.
   *
   * If this column is included in the query predicate, the table will generate
   * optimized information. Consider the system_controls table, a default filter
   * without a query predicate lists all of the keys. When a specific domain is
   * included in the predicate then the table will only issue syscalls/lookups
   * for that domain, greatly optimizing the time and utilization.
   *
   * This optimization does not mean the column is an index.
   */
  OPTIMIZED = 8,

  /// This column should be hidden from '*'' selects.
  HIDDEN = 16,
};

/// Treat column options as a set of flags.
inline ColumnOptions operator|(ColumnOptions a, ColumnOptions b) {
  return static_cast<ColumnOptions>(static_cast<int>(a) | static_cast<int>(b));
}

/// Treat column options as a set of flags.
inline size_t operator&(ColumnOptions a, ColumnOptions b) {
  return static_cast<size_t>(a) & static_cast<size_t>(b);
}

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

  /// This table's data requires an osquery kernel extension/module.
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

/// Helper alias for TablePlugin names.
using TableName = std::string;

/// Alias for an ordered list of column name and corresponding SQL type.
using TableColumns =
    std::vector<std::tuple<std::string, ColumnType, ColumnOptions>>;

/// Alias for map of column alias sets.
using ColumnAliasSet = std::map<std::string, std::set<std::string>>;

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
  std::set<T> getAll(ConstraintOperator op) const {
    std::set<T> literal_matches;
    auto matches = getAll(op);
    for (const auto& match : matches) {
      literal_matches.insert(AS_LITERAL(T, match));
    }
    return literal_matches;
  }

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
  void serialize(boost::property_tree::ptree& tree) const;

  /// See ConstraintList::unserialize.
  void unserialize(const boost::property_tree::ptree& tree);

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
  std::map<std::string, Row> cache;
};

using RowGenerator = boost::coroutines2::coroutine<Row&>;
using RowYield = RowGenerator::push_type;

/**
 * @brief A QueryContext is provided to every table generator for optimization
 * on query components like predicate constraints and limits.
 */
struct QueryContext : private only_movable {
  /// Construct a context without cache support.
  QueryContext() : table_(new VirtualTableContent()) {}

  /// If the context was created without content, it is ephemeral.
  ~QueryContext() {
    if (!enable_cache_ && table_ != nullptr) {
      delete table_;
      table_ = nullptr;
    }
  }

  /// Construct a context and set the table content for caching.
  explicit QueryContext(VirtualTableContent* content)
      : enable_cache_(true), table_(content) {}

  /// Allow moving.
  QueryContext(QueryContext&&) = default;

  /// Allow move assignment.
  QueryContext& operator=(QueryContext&&) = delete;

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

  /// Check if a table-defined index exists within the query cache.
  bool isCached(const std::string& index) const;

  /// Retrieve an index within the query cache.
  const Row& getCache(const std::string& index);

  /// Helper to retrieve a keyed element within the query cache.
  const std::string& getCache(const std::string& index, const std::string& key);

  /// Request the context use the warm query cache.
  void useCache(bool use_cache);

  /// Check if the query requested use of the warm query cache.
  bool useCache() const;

  /// Set the entire cache for an index.
  void setCache(const std::string& index, Row _cache);

  /// Helper to set a keyed element within the query cache.
  void setCache(const std::string& index,
                const std::string& key,
                std::string _item);

  /// The map of column name to constraint list.
  ConstraintMap constraints;

 private:
  /// If false then the context is maintaining an ephemeral cache.
  bool enable_cache_{false};

  /// If the context is allowed to use the warm query cache.
  bool use_cache_{false};

  /// Persistent table content for table caching.
  VirtualTableContent* table_{nullptr};

 private:
  friend class TablePlugin;
};

using QueryContext = struct QueryContext;
using Constraint = struct Constraint;

class TableCache {
public:
  virtual ~TableCache() {}

  virtual const std::string getTableName() const = 0;

  virtual bool isEnabled() const = 0;

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
   * @param interval The interval this query expects the tables results.
   * @return True if the cache contains fresh results, otherwise false.
   */
  virtual bool isCached() const = 0;

  /**
   * @brief Perform a database lookup of cached results and deserialize.
   *
   * If a query determined the table's cached results are fresh, it may ask the
   * table to retrieve results from the database and deserialized them into
   * table row data.
   *
   * @return The deserialized row data of cached results.
   */
  virtual QueryData get() const = 0;

  /**
   * @brief Similar to getCache, stores the results from generate.
   *
   * Set will serialize and save the results to be retrieved later.
   */
  virtual void set(const QueryData& results) = 0;

};

/*
 * Implementation of TableCache for tables that should not be cached.
 */
class TableCacheDisabled : public TableCache {
public:
  TableCacheDisabled(const std::string tableName) : tableName_(tableName) {}

  virtual ~TableCacheDisabled() {}

  virtual bool isEnabled() const { return false; }

  virtual const std::string getTableName() const { return tableName_; }

  virtual bool isCached() const { return false; }

  virtual QueryData get() const { return QueryData(); }

  virtual void set(const QueryData& results) {}

private:
  const std::string tableName_;
};

/*
 * @param disabled If true, then TableCacheDisabled instance returned, otherwise TableCacheDB instance
 */
TableCache* TableCacheNew(const std::string tableName, bool disabled);

struct TableDefinition {
  std::string              name;
  std::vector<std::string> aliases;
  TableColumns             columns;
  ColumnAliasSet           columnAliases;
  TableAttributes          attributes;
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

   TablePlugin(const TableDefinition& tdef) : Plugin(), tableDef_(tdef), cache_(*TableCacheNew(tdef.name, (tdef.attributes & TableAttributes::CACHEABLE)))
   {}

   const TableDefinition& definition() const { return tableDef_; }

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
  virtual QueryData generate(QueryContext& context) {
    (void)context;
    return QueryData();
  }

  virtual TableCache& cache() { return cache_; }

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
   const TableDefinition &tableDef_;
   TableCache &cache_;



  /// An SQL table containing the table definition/syntax.
  //std::string columnDefinition() const;

  /// Return the name and column pairs for attaching virtual tables.
  PluginResponse routeInfo() const override;

#ifdef NEVER
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
  bool isCached(size_t interval, const QueryContext& ctx) const;

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

  /**
   * @brief Similar to getCache, stores the results from generate.
   *
   * Set will serialize and save the results as JSON to be retrieved later.
   * It will inspect the query context, if any required/indexed/optimized or
   * additional columns are used then the cache will not be saved.
   */
  void setCache(size_t step,
                size_t interval,
                const QueryContext& ctx,
                const QueryData& results);

 private:
  /// The last time in seconds the table data results were saved to cache.
  size_t last_cached_{0};

  /// The last interval in seconds when the table data was cached.
  size_t last_interval_{0};
#endif // NEVER

 public:
  /**
   * @brief The scheduled interval for the executing query.
   *
   * Scheduled queries execute within a pseudo-mutex, and each may communicate
   * their scheduled interval to internal TablePlugin implementations. If the
   * table is cachable then the interval can be used to calculate freshness.
   */
  //static size_t kCacheInterval;

  /// The schedule step, this is the current position of the schedule.
  //static size_t kCacheStep;

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
  friend class RegistryFactory;
  FRIEND_TEST(VirtualTableTests, test_tableplugin_columndefinition);
  FRIEND_TEST(VirtualTableTests, test_tableplugin_statement);
  FRIEND_TEST(VirtualTableTests, test_indexing_costs);
  FRIEND_TEST(VirtualTableTests, test_table_results_cache);
  FRIEND_TEST(VirtualTableTests, test_yield_generator);
};

/// Helper method to generate the virtual table CREATE statement.
std::string columnDefinition(const TableColumns& columns);

/// Helper method to generate the virtual table CREATE statement.
std::string columnDefinition(const PluginResponse& response,
                             bool aliases = false);

/// Get the string representation for an SQLite column type.
inline const std::string& columnTypeName(ColumnType type) {
  return kColumnTypeNames.at(type);
}

/// Get the column type from the string representation.
ColumnType columnTypeName(const std::string& type);
} // namespace osquery
