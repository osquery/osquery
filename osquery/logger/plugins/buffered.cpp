/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>
#include <chrono>
#include <thread>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/database.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/system.h>

#include "osquery/config/parsers/decorators.h"
#include "osquery/logger/plugins/buffered.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(uint64,
     buffered_log_max,
     1000000,
     "Maximum number of logs in buffered output plugins (0 = unlimited)");

const auto BufferedLogForwarder::kLogPeriod = std::chrono::seconds(4);
const size_t BufferedLogForwarder::kMaxLogLines = 1024;

void BufferedLogForwarder::check() {
  // Get a list of all the buffered log items, with a max of 1024 lines.
  std::vector<std::string> indexes;
  auto status = scanDatabaseKeys(kLogs, indexes, index_name_, max_log_lines_);

  // For each index, accumulate the log line into the result or status set.
  std::vector<std::string> results, statuses;
  iterate(indexes, ([&results, &statuses, this](std::string& index) {
            std::string value;
            auto& target = isResultIndex(index) ? results : statuses;
            if (getDatabaseValue(kLogs, index, value)) {
              target.push_back(std::move(value));
            }
          }));

  // If any results/statuses were found in the flushed buffer, send.
  if (results.size() > 0) {
    status = send(results, "result");
    if (!status.ok()) {
      VLOG(1) << "Error sending results to logger: " << status.getMessage();
    } else {
      // Clear the results logs once they were sent.
      iterate(indexes, ([this](std::string& index) {
                if (!isResultIndex(index)) {
                  return;
                }
                std::lock_guard<std::recursive_mutex> lock(count_mutex_);
                deleteValueWithCount(kLogs, index);
              }));
    }
  }

  if (statuses.size() > 0) {
    status = send(statuses, "status");
    if (!status.ok()) {
      VLOG(1) << "Error sending status to logger: " << status.getMessage();
    } else {
      // Clear the status logs once they were sent.
      iterate(indexes, ([this](std::string& index) {
                if (!isStatusIndex(index)) {
                  return;
                }
                std::lock_guard<std::recursive_mutex> lock(count_mutex_);
                deleteValueWithCount(kLogs, index);
              }));
    }
  }

  // Purge any logs exceeding the max after our send attempt
  if (FLAGS_buffered_log_max > 0) {
    purge();
  }
}

void BufferedLogForwarder::purge() {
  std::lock_guard<std::recursive_mutex> lock(count_mutex_);
  size_t buffer_count = getBufferCount();
  if (buffer_count <= FLAGS_buffered_log_max) {
    return;
  }

  size_t purge_count = buffer_count - FLAGS_buffered_log_max;

  // Collect purge_count indexes of each type (result/status) before
  // partitioning to find the oldest. Note this assumes that the indexes are
  // returned in ascending lexicographic order (true for RocksDB).
  std::vector<std::string> indexes;
  auto status =
      scanDatabaseKeys(kLogs, indexes, genIndexPrefix(true), purge_count);
  if (!status.ok()) {
    LOG(ERROR) << "Error scanning DB during buffered log purge";
    return;
  }

  std::vector<std::string> status_indexes;
  status = scanDatabaseKeys(kLogs, status_indexes, genIndexPrefix(false),
                            purge_count);
  if (!status.ok()) {
    LOG(ERROR) << "Error scanning DB during buffered log purge";
    return;
  }

  indexes.insert(indexes.end(), status_indexes.begin(), status_indexes.end());

  size_t prefix_size = genIndexPrefix(true).size();
  // Partition the indexes so that the first purge_count elements are the
  // oldest indexes (the ones to be purged)
  std::nth_element(indexes.begin(), indexes.begin() + purge_count - 1,
                   indexes.end(),
                   [&](const std::string& a, const std::string& b) {
                     // Skip the prefix when doing comparisons
                     return a.compare(prefix_size, std::string::npos, b,
                                      prefix_size, std::string::npos) < 0;
                   });
  indexes.erase(indexes.begin() + purge_count, indexes.end());

  // Now only indexes of logs to be deleted remain
  iterate(indexes, [this](const std::string& index) {
    if (!deleteValueWithCount(kLogs, index).ok()) {
      LOG(ERROR) << "Error deleting value during buffered log purge";
    }
  });

  LOG(WARNING) << purge_count << " buffered logs purged (max "
               << FLAGS_buffered_log_max << ")";
}

void BufferedLogForwarder::start() {
  while (!interrupted()) {
    check();

    // Cool off and time wait the configured period.
    pauseMilli(log_period_);
  }
}

Status BufferedLogForwarder::logString(const std::string& s) {
  std::string index = genResultIndex();
  std::lock_guard<std::recursive_mutex> lock(count_mutex_);
  return addValueWithCount(kLogs, index, s);
}

Status BufferedLogForwarder::logStatus(const std::vector<StatusLogLine>& log) {
  // Append decorations to status
  // Assemble a decorations tree to append to each status buffer line.
  pt::ptree dtree;
  std::map<std::string, std::string> decorations;
  getDecorations(decorations);
  for (const auto& decoration : decorations) {
    dtree.put(decoration.first, decoration.second);
  }

  for (const auto& item : log) {
    // Convert the StatusLogLine into ptree format, to convert to JSON.
    pt::ptree buffer;
    buffer.put("severity", (google::LogSeverity)item.severity);
    buffer.put("filename", item.filename);
    buffer.put("line", item.line);
    buffer.put("message", item.message);
    buffer.put("version", kVersion);
    if (decorations.size() > 0) {
      buffer.put_child("decorations", dtree);
    }

    // Convert to JSON, for storing a string-representation in the database.
    std::string json;
    try {
      std::stringstream json_output;
      pt::write_json(json_output, buffer, false);
      json = json_output.str();
    } catch (const pt::json_parser::json_parser_error& e) {
      // The log could not be represented as JSON.
      return Status(1, e.what());
    }

    // Store the status line in a backing store.
    if (!json.empty()) {
      json.pop_back();
    }
    std::string index = genStatusIndex();
    std::lock_guard<std::recursive_mutex> lock(count_mutex_);
    Status status = addValueWithCount(kLogs, index, json);
    if (!status.ok()) {
      // Do not continue if any line fails.
      return status;
    }
  }

  return Status(0);
}

bool BufferedLogForwarder::isIndex(const std::string& index, bool results) {
  size_t target = index_name_.size() + 1;
  return target < index.size() && index.at(target) == (results ? 'r' : 's');
}

bool BufferedLogForwarder::isResultIndex(const std::string& index) {
  return isIndex(index, true);
}

bool BufferedLogForwarder::isStatusIndex(const std::string& index) {
  return isIndex(index, false);
}

std::string BufferedLogForwarder::genResultIndex() { return genIndex(true); }

std::string BufferedLogForwarder::genStatusIndex() { return genIndex(false); }

std::string BufferedLogForwarder::genIndexPrefix(bool results) {
  return index_name_ + "_" + ((results) ? "r" : "s") + "_";
}

std::string BufferedLogForwarder::genIndex(bool results) {
  return genIndexPrefix(results) + std::to_string(getUnixTime()) + "_" +
         std::to_string(++log_index_);
}

size_t BufferedLogForwarder::getBufferCount() {
  std::call_once(init_count_flag_, [this]() {
    // init the count
    std::vector<std::string> indexes;
    auto status = scanDatabaseKeys(kLogs, indexes, index_name_, 0);

    if (!status.ok()) {
      LOG(ERROR) << "Error scanning DB for count of buffered logs. Purging may "
                    "not take place as expected.";
      buffer_count_ = 0;
      return;
    }

    buffer_count_ = indexes.size();
  });

  return buffer_count_;
}

Status BufferedLogForwarder::addValueWithCount(const std::string& domain,
                                               const std::string& key,
                                               const std::string& value) {
  size_t prev_count = getBufferCount();
  Status status = setDatabaseValue(domain, key, value);
  if (status.ok()) {
    setBufferCount(prev_count + 1);
  }
  return status;
}

Status BufferedLogForwarder::deleteValueWithCount(const std::string& domain,
                                                  const std::string& key) {
  size_t prev_count = getBufferCount();
  Status status = deleteDatabaseValue(domain, key);
  if (status.ok()) {
    setBufferCount(prev_count - 1);
  }
  return status;
}
}
