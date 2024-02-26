/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "query_performance.h"
#include "boost/lexical_cast.hpp"
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <string>

namespace osquery {

// Helper function to convert a string to a given type.
template <typename Result>
Result convert(const std::string& source) {
  Result result;
  if (!boost::conversion::try_lexical_convert<Result>(source, result)) {
    return Result();
  }
  return result;
}

QueryPerformance::QueryPerformance(const std::string& csv) {
  std::vector<std::string> parts;
  boost::split(parts, csv, boost::is_any_of(","));
  // future proofing the size, in case additional fields are added
  if (parts.size() < 12) {
    return;
  }

  executions = convert<std::size_t>(parts[0]);
  last_executed = convert<std::uint64_t>(parts[1]);
  wall_time = convert<std::uint64_t>(parts[2]);
  wall_time_ms = convert<std::uint64_t>(parts[3]);
  last_wall_time_ms = convert<std::uint64_t>(parts[4]);
  user_time = convert<std::uint64_t>(parts[5]);
  last_user_time = convert<std::uint64_t>(parts[6]);
  system_time = convert<std::uint64_t>(parts[7]);
  last_system_time = convert<std::uint64_t>(parts[8]);
  average_memory = convert<std::uint64_t>(parts[9]);
  last_memory = convert<std::uint64_t>(parts[10]);
  output_size = convert<std::uint64_t>(parts[11]);
}

std::string QueryPerformance::toCSV() const {
  return std::to_string(executions) + "," + std::to_string(last_executed) +
         "," + std::to_string(wall_time) + "," + std::to_string(wall_time_ms) +
         "," + std::to_string(last_wall_time_ms) + "," +
         std::to_string(user_time) + "," + std::to_string(last_user_time) +
         "," + std::to_string(system_time) + "," +
         std::to_string(last_system_time) + "," +
         std::to_string(average_memory) + "," + std::to_string(last_memory) +
         "," + std::to_string(output_size);
}

bool operator==(const QueryPerformance& l, const QueryPerformance& r) {
  return std::tie(l.executions,
                  l.last_executed,
                  l.wall_time,
                  l.wall_time_ms,
                  l.last_wall_time_ms,
                  l.user_time,
                  l.last_user_time,
                  l.system_time,
                  l.last_system_time,
                  l.average_memory,
                  l.last_memory,
                  l.output_size) == std::tie(r.executions,
                                             r.last_executed,
                                             r.wall_time,
                                             r.wall_time_ms,
                                             r.last_wall_time_ms,
                                             r.user_time,
                                             r.last_user_time,
                                             r.system_time,
                                             r.last_system_time,
                                             r.average_memory,
                                             r.last_memory,
                                             r.output_size);
}

} // namespace osquery
