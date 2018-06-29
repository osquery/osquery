/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <unordered_map>

#include <boost/format.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/numeric_monitoring.h>
#include <osquery/numeric_monitoring/plugin_interface.h>
#include <osquery/registry_factory.h>

namespace osquery {

FLAG(bool,
     enable_numeric_monitoring,
     false,
     "Enable numeric monitoring system");
FLAG(string,
     numeric_monitoring_plugins,
     "filesystem",
     "Coma separated numeric monitoring plugins names");

namespace monitoring {

namespace {

template <typename KeyType, typename ValueType>
inline auto reverseMap(const std::unordered_map<KeyType, ValueType>& straight) {
  auto reversed = std::unordered_map<ValueType, KeyType>{};
  for (const auto& item : straight) {
    reversed.emplace(item.second, item.first);
  }
  return reversed;
}

const auto& getAggregationTypeToStringTable() {
  const auto static table = std::unordered_map<AggregationType, std::string>{
      {AggregationType::None, "none"},
      {AggregationType::Sum, "sum"},
      {AggregationType::Min, "min"},
      {AggregationType::Max, "max"},
  };
  return table;
}

const auto& getStringToAggregationTypeTable() {
  const auto static table = reverseMap(getAggregationTypeToStringTable());
  return table;
}

} // namespace

Expected<AggregationType, TemporaryErrorType>
tryDeserializeAggregationTypeFromString(const std::string& from) {
  auto it = getStringToAggregationTypeTable().find(from);
  if (it == getStringToAggregationTypeTable().end()) {
    return createError(
        TemporaryErrorType::InvalidArgument,
        boost::str(
            boost::format(
                "Wrong string representation of `AggregationType`: \"%s\"") %
            from));
  }
  return it->second;
}

Expected<std::string, TemporaryErrorType> trySerializeAggregationTypeToString(
    const AggregationType& from) {
  auto it = getAggregationTypeToStringTable().find(from);
  if (it == getAggregationTypeToStringTable().end()) {
    return createError(TemporaryErrorType::InvalidArgument,
                       "Such `AggregationType` does not exist");
  }
  return it->second;
}

void record(const std::string& path,
            ValueType value,
            AggregationType aggr_type,
            TimePoint timePoint) {
  if (!FLAGS_enable_numeric_monitoring) {
    return;
  }
  auto aggrTypeStringRepr = std::string{};
  {
    auto repr = tryTo<std::string>(aggr_type);
    aggrTypeStringRepr = repr ? repr.take() : "";
  }
  auto status =
      Registry::call(registryName(),
                     FLAGS_numeric_monitoring_plugins,
                     {
                         {recordKeys().path, path},
                         {recordKeys().value, std::to_string(value)},
                         {recordKeys().timestamp,
                          std::to_string(timePoint.time_since_epoch().count())},
                         {recordKeys().aggregation, aggrTypeStringRepr},
                     });
  if (!status.ok()) {
    LOG(ERROR) << "Failed to send numeric monitoring record: " << status.what();
  }
}

} // namespace monitoring
} // namespace osquery
