/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <unordered_map>

#include <boost/io/quoted.hpp>

#include <osquery/core/flags.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/logger/logger.h>
#include <osquery/numeric_monitoring/numeric_monitoring.h>
#include <osquery/numeric_monitoring/plugin_interface.h>
#include <osquery/numeric_monitoring/pre_aggregation_cache.h>
#include <osquery/registry/registry_factory.h>

#include <osquery/utils/enum_class_hash.h>

namespace osquery {

FLAG(bool,
     enable_numeric_monitoring,
     false,
     "Enable numeric monitoring system");
FLAG(string,
     numeric_monitoring_plugins,
     "filesystem",
     "Comma separated numeric monitoring plugins names");
FLAG(uint64,
     numeric_monitoring_pre_aggregation_time,
     60,
     "Time period in seconds for numeric monitoring pre-aggregation buffer.");

namespace {
using monitoring::PreAggregationType;

template <typename KeyType, typename ValueType, typename... Other>
inline auto reverseMap(
    const std::unordered_map<KeyType, ValueType, Other...>& straight) {
  auto reversed = std::unordered_map<ValueType, KeyType>{};
  for (const auto& item : straight) {
    reversed.emplace(item.second, item.first);
  }
  return reversed;
}

const auto& getAggregationTypeToStringTable() {
  const auto static table =
      std::unordered_map<PreAggregationType, std::string, EnumClassHash>{
          {PreAggregationType::None, "none"},
          {PreAggregationType::Sum, "sum"},
          {PreAggregationType::Min, "min"},
          {PreAggregationType::Max, "max"},
          {PreAggregationType::Avg, "avg"},
          {PreAggregationType::Stddev, "stddev"},
          {PreAggregationType::P10, "p10"},
          {PreAggregationType::P50, "p50"},
          {PreAggregationType::P95, "p95"},
          {PreAggregationType::P99, "p99"}};
  return table;
}

const auto& getStringToAggregationTypeTable() {
  const auto static table = reverseMap(getAggregationTypeToStringTable());
  return table;
}

} // namespace

template <>
std::string to<std::string>(const monitoring::PreAggregationType& from) {
  auto it = getAggregationTypeToStringTable().find(from);
  if (it == getAggregationTypeToStringTable().end()) {
    LOG(ERROR) << "Unknown PreAggregationType "
               << static_cast<std::underlying_type<PreAggregationType>::type>(
                      from)
               << " could not be converted to the string";
    return "";
  }
  return it->second;
}

template <>
Expected<monitoring::PreAggregationType, ConversionError>
tryTo<monitoring::PreAggregationType>(const std::string& from) {
  auto it = getStringToAggregationTypeTable().find(from);
  if (it == getStringToAggregationTypeTable().end()) {
    return createError(ConversionError::InvalidArgument)
           << "Wrong string representation of `PreAggregationType`: "
           << boost::io::quoted(from);
  }
  return it->second;
}

namespace monitoring {

namespace {

class FlusherIsScheduled {};
FlusherIsScheduled schedule();

class PreAggregationBuffer final {
 public:
  static PreAggregationBuffer& get() {
    static PreAggregationBuffer instance{};
    static auto const flusher_is_scheduled = schedule();
    boost::ignore_unused(flusher_is_scheduled);
    return instance;
  }

  void record(const std::string& path,
              const ValueType& value,
              const PreAggregationType& pre_aggregation,
              const bool sync,
              const TimePoint& time_point) {
    if (0 == FLAGS_numeric_monitoring_pre_aggregation_time || sync) {
      dispatchOne(path, value, pre_aggregation, sync, time_point);
    } else {
      std::lock_guard<std::mutex> lock(mutex_);
      cache_.addPoint(Point(path, value, pre_aggregation, time_point));
    }
  }

  void flush() {
    auto points = takeCachedPoints();
    for (const auto& pt : points) {
      dispatchOne(
          pt.path_, pt.value_, pt.pre_aggregation_type_, false, pt.time_point_);
    }
  }

 private:
  std::vector<Point> takeCachedPoints() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto points = cache_.takePoints();
    return points;
  }

  void dispatchOne(const std::string& path,
                   const ValueType& value,
                   const PreAggregationType& pre_aggregation,
                   const bool sync,
                   const TimePoint& time_point) {
    auto status = Registry::call(
        registryName(),
        FLAGS_numeric_monitoring_plugins,
        {
            {recordKeys().path, path},
            {recordKeys().value, std::to_string(value)},
            {recordKeys().pre_aggregation, to<std::string>(pre_aggregation)},
            {recordKeys().timestamp,
             std::to_string(time_point.time_since_epoch().count())},
            {recordKeys().sync, sync ? "true" : "false"},
        });
    if (!status.ok()) {
      LOG(ERROR) << "Data loss. Numeric monitoring point dispatch failed: "
                 << status.what();
    }
  }

 private:
  PreAggregationCache cache_;
  std::mutex mutex_;
};

class PreAggregationFlusher : public InternalRunnable {
 public:
  explicit PreAggregationFlusher()
      : InternalRunnable("numeric_monitoring_pre_aggregation_buffer_flusher") {}

  void start() override {
    while (!interrupted() &&
           0 != FLAGS_numeric_monitoring_pre_aggregation_time) {
      pause(
          std::chrono::seconds(FLAGS_numeric_monitoring_pre_aggregation_time));
      PreAggregationBuffer::get().flush();
    }
  }
};

FlusherIsScheduled schedule() {
  Dispatcher::addService(std::make_shared<PreAggregationFlusher>());
  return FlusherIsScheduled{};
}

} // namespace

void flush() {
  PreAggregationBuffer::get().flush();
}

void record(const std::string& path,
            ValueType value,
            PreAggregationType pre_aggregation,
            const bool sync,
            TimePoint time_point) {
  if (!FLAGS_enable_numeric_monitoring) {
    return;
  }
  PreAggregationBuffer::get().record(
      path, value, pre_aggregation, sync, std::move(time_point));
}

} // namespace monitoring
} // namespace osquery
