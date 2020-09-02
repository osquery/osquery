/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <string>

#include <osquery/utils/only_movable.h>

namespace osquery {

/**
 * @brief Represents the relevant parameters of a scheduled query.
 *
 * Within the context of osqueryd, a scheduled query may have many relevant
 * attributes. Those attributes are represented in this data structure.
 */
struct ScheduledQuery : private only_movable {
  /// Name of the pack containing query
  std::string pack_name;

  /// Name of the query
  std::string name;

  /// The SQL query.
  std::string query;

  /// Owner of the query
  std::string oncall;

  /// How often the query should be executed, in second.
  uint64_t interval{0};

  /// A temporary splayed internal.
  uint64_t splayed_interval{0};

  /**
   * @brief Queries are denylisted based on logic in the configuration.
   *
   * Most calls to inspect scheduled queries will abstract away the denylisting
   * concept and only return non-denylisted queries. The config may be asked
   * to return all queries, thus it is important to capture this optional data.
   */
  bool denylisted{false};

  /// Set of query options.
  std::map<std::string, bool> options;

  ScheduledQuery(const std::string& pack_name,
                 const std::string& name,
                 const std::string& query)
      : pack_name(pack_name), name(name), query(query) {}
  ScheduledQuery() = default;
  ScheduledQuery(ScheduledQuery&&) = default;
  ScheduledQuery& operator=(ScheduledQuery&&) = default;

  /**
   * @brief Returns true if the query is a snapshot query, otherwise false.
   *
   * @return A bool indicating if this query is a snapshot query.
   */
  inline bool isSnapshotQuery() const {
    auto it = options.find("snapshot");
    return it != options.end() && it->second;
  }

  /**
   * @brief Returns true if removed rows should be reported, otherwise false.
   *
   * @return A bool indicating if this query reports removed rows.
   */
  inline bool reportRemovedRows() const {
    auto it = options.find("removed");

    if (it == options.end()) {
      // If the option is missing, we do want to report removed rows.
      return true;
    }

    return it->second;
  }

  /// equals operator
  bool operator==(const ScheduledQuery& comp) const {
    return (comp.query == query) && (comp.interval == interval);
  }

  /// not equals operator
  bool operator!=(const ScheduledQuery& comp) const {
    return !(*this == comp);
  }
};

} // namespace osquery
