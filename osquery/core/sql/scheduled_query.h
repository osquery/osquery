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

#include <string>
#include <map>

#include <osquery/utils/only_movable.h>

namespace osquery {

/**
 * @brief Represents the relevant parameters of a scheduled query.
 *
 * Within the context of osqueryd, a scheduled query may have many relevant
 * attributes. Those attributes are represented in this data structure.
 */
struct ScheduledQuery : private only_movable {
 public:
  /// The SQL query.
  std::string query;

  /// How often the query should be executed, in second.
  size_t interval{0};

  /// A temporary splayed internal.
  size_t splayed_interval{0};

  /**
   * @brief Queries are blacklisted based on logic in the configuration.
   *
   * Most calls to inspect scheduled queries will abstract away the blacklisting
   * concept and only return non-blacklisted queries. The config may be asked
   * to return all queries, thus it is important to capture this optional data.
   */
  bool blacklisted{false};

  /// Set of query options.
  std::map<std::string, bool> options;

  ScheduledQuery() = default;
  ScheduledQuery(ScheduledQuery&&) = default;
  ScheduledQuery& operator=(ScheduledQuery&&) = default;

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
