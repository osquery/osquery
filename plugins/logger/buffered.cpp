/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "buffered.h"

#include <algorithm>
#include <chrono>
#include <thread>

#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/utils/info/version.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/time.h>
#include <plugins/config/parsers/decorators.h>

namespace osquery {

FLAG(uint64,
     buffered_log_max,
     1000000,
     "Maximum number of logs in buffered output plugins (0 = unlimited)");

FLAG(uint64,
     buffered_log_max_batch_bytes,
     16 * 1024 * 1024,
     "Maximum bytes of logs that buffered output plugins read and send at "
     "once, per log type (0 = unlimited)");

DECLARE_bool(decorations_top_level);

const std::chrono::seconds BufferedLogForwarder::kLogPeriod{
    std::chrono::seconds(4)};
const uint64_t BufferedLogForwarder::kMaxLogLines{1024};

Status BufferedLogForwarder::setUp() {
  // initialize buffer_count_ by scanning the DB
  std::vector<std::string> indexes;
  auto status = scanDatabaseKeys(kLogs, indexes, index_name_, (uint64_t)0);

  if (!status.ok()) {
    return Status(1, "Error scanning for buffered log count");
  }

  RecursiveLock lock(count_mutex_);
  buffer_count_ = indexes.size();
  return Status(0);
}

void BufferedLogForwarder::check(bool send_results, bool send_statuses) {
  // Get a list of all the buffered log items, with a max of 1024 lines.
  std::vector<std::string> indexes;
  scanDatabaseKeys(kLogs, indexes, index_name_, max_log_lines_);

  // Each log type is read and sent separately, so only one type's lines are
  // held in memory at a time, and a type that is backing off is not read.
  if (send_results && !checkType(indexes, true)) {
    return;
  }
  if (send_statuses && !checkType(indexes, false)) {
    return;
  }

  // Purge any logs exceeding the max after our send attempt
  if (FLAGS_buffered_log_max > 0) {
    purge();
  }
}

bool BufferedLogForwarder::checkType(std::vector<std::string>& indexes,
                                     bool results) {
  const std::string log_type = results ? "result" : "status";
  auto& backoff = results ? results_backoff_ : statuses_backoff_;
  auto& backoff_period =
      results ? results_backoff_period_ : statuses_backoff_period_;
  auto& send_failing = results ? results_send_failing_ : statuses_send_failing_;

  // Accumulate this type's log lines, up to the batch size limit. The first
  // line is always taken, so a line larger than the limit is still sent.
  std::vector<std::string> lines;
  std::vector<std::string> batch_indexes;
  size_t batch_bytes = 0;
  bool batch_full = false;
  iterate(
      indexes, ([&](std::string& index) {
        if (batch_full || !isIndex(index, results)) {
          return;
        }
        std::string value;
        if (getDatabaseValue(kLogs, index, value)) {
          if (FLAGS_buffered_log_max_batch_bytes > 0 && !lines.empty() &&
              batch_bytes + value.size() > FLAGS_buffered_log_max_batch_bytes) {
            // Leave this line, and the rest, for the next check.
            batch_full = true;
            return;
          }
          batch_bytes += value.size();
          lines.emplace_back(std::move(value));
        }
        batch_indexes.push_back(index);
      }));

  if (lines.empty()) {
    return true;
  }

  auto status = send(lines, log_type);
  if (!status.ok()) {
    // Warn on the first failure only, since sending is retried every period.
    if (!send_failing) {
      LOG(WARNING) << "Error sending " << log_type
                   << " logs to logger: " << status.getMessage();
      send_failing = true;
    } else {
      VLOG(1) << "Error sending " << log_type
              << " logs to logger: " << status.getMessage();
    }

    if (interrupted()) {
      return false;
    }
    if (max_backoff_period_ > std::chrono::seconds::zero()) {
      backoff++;
      // Apply exponential backoff time.
      backoff_period = log_period_ * backoff * backoff;
      if (backoff_period > max_backoff_period_) {
        backoff_period = max_backoff_period_;
        backoff--;
      }
      VLOG(1) << "Will attempt to send " << log_type << " logs again in "
              << backoff_period.count() << " seconds";
    }
    return true;
  }

  // Clear the logs once they were sent.
  iterate(batch_indexes,
          ([this](std::string& index) { deleteValueWithCount(kLogs, index); }));
  if (send_failing) {
    LOG(INFO) << "Resumed sending " << log_type << " logs to logger";
    send_failing = false;
  }
  backoff = 0;
  backoff_period = std::chrono::seconds::zero();
  return true;
}

void BufferedLogForwarder::purge() {
  RecursiveLock lock(count_mutex_);
  if (buffer_count_ <= FLAGS_buffered_log_max) {
    return;
  }

  unsigned long long int purge_count = buffer_count_ - FLAGS_buffered_log_max;

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

  LOG(WARNING) << "Purging buffered logs limit (" << FLAGS_buffered_log_max
               << ") exceeded: " << buffer_count_;

  std::vector<std::string> status_indexes;
  status = scanDatabaseKeys(
      kLogs, status_indexes, genIndexPrefix(false), purge_count);
  if (!status.ok()) {
    LOG(ERROR) << "Error scanning DB during buffered log purge";
    return;
  }

  indexes.insert(indexes.end(), status_indexes.begin(), status_indexes.end());

  if (indexes.size() < purge_count) {
    LOG(ERROR) << "Trying to purge " << purge_count << " logs but only found "
               << indexes.size();
    return;
  }

  size_t prefix_size = genIndexPrefix(true).size();
  // Partition the indexes so that the first purge_count elements are the
  // oldest indexes (the ones to be purged)
  std::nth_element(indexes.begin(),
                   indexes.begin() + (unsigned int)purge_count - 1,
                   indexes.end(),
                   [&](const std::string& a, const std::string& b) {
                     // Skip the prefix when doing comparisons
                     return a.compare(prefix_size,
                                      std::string::npos,
                                      b,
                                      prefix_size,
                                      std::string::npos) < 0;
                   });
  indexes.erase(indexes.begin() + (unsigned int)purge_count, indexes.end());

  // Now only indexes of logs to be deleted remain
  iterate(indexes, [this](const std::string& index) {
    if (!deleteValueWithCount(kLogs, index).ok()) {
      LOG(ERROR) << "Error deleting value during buffered log purge";
    }
  });
}

void BufferedLogForwarder::start() {
  while (!interrupted()) {
    bool send_results = results_backoff_period_ <= std::chrono::seconds::zero();
    bool send_statuses =
        statuses_backoff_period_ <= std::chrono::seconds::zero();
    check(send_results, send_statuses);

    do {
      // Cool off and time wait the configured period.
      pause(std::chrono::milliseconds(log_period_));
      // Apply any updates to configuration options, such as disabling of
      // backoff.
      applyNewConfiguration();
      // Update backoff timers.
      backoffTick();
    } while (!interrupted() &&
             results_backoff_period_ > std::chrono::seconds::zero() &&
             statuses_backoff_period_ > std::chrono::seconds::zero());
  }
}

void BufferedLogForwarder::backoffTick() {
  // Check if backoff was cancelled.
  if (max_backoff_period_ <= log_period_) {
    results_backoff_period_ = std::chrono::seconds::zero();
    statuses_backoff_period_ = std::chrono::seconds::zero();
    results_backoff_ = 0;
    statuses_backoff_ = 0;
  } else {
    // Otherwise keep backing off, but reduce the amount of time left.
    if (results_backoff_period_ > std::chrono::seconds::zero()) {
      results_backoff_period_ -= log_period_;
    }
    if (statuses_backoff_period_ > std::chrono::seconds::zero()) {
      statuses_backoff_period_ -= log_period_;
    }
  }
}

Status BufferedLogForwarder::logString(const std::string& s, uint64_t time) {
  std::string index = genResultIndex(time);
  return addValueWithCount(kLogs, index, s);
}

Status BufferedLogForwarder::logStatus(const std::vector<StatusLogLine>& log,
                                       uint64_t time) {
  // Append decorations to status
  std::map<std::string, std::string> decorations;
  getDecorations(decorations);

  for (const auto& item : log) {
    // Convert the StatusLogLine into JSON.
    JSON status_json;
    status_json.addRef("hostIdentifier", item.identifier);
    status_json.addRef("calendarTime", item.calendar_time);
    status_json.addCopy("unixTime", item.time);
    status_json.addCopy("severity", (google::LogSeverity)item.severity);
    status_json.addRef("filename", item.filename);
    status_json.addCopy("line", item.line);
    status_json.addRef("message", item.message);
    status_json.addRef("version", kVersion);

    if (!decorations.empty()) {
      if (!FLAGS_decorations_top_level) {
        JSON decorations_json;
        for (const auto& decoration : decorations) {
          decorations_json.addCopy(decoration.first, decoration.second);
        }

        status_json.addCopy("decorations", decorations_json.doc());
      } else {
        for (const auto& decoration : decorations) {
          status_json.addCopy(decoration.first, decoration.second);
        }
      }
    }

    // Convert to JSON, for storing a string-representation in the database.
    std::string json;
    auto status = status_json.toString(json);

    if (!status.ok()) {
      return status;
    }

    // Store the status line in a backing store.
    std::string index = genStatusIndex(time);
    status = addValueWithCount(kLogs, index, json);
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

std::string BufferedLogForwarder::genResultIndex(uint64_t time) {
  return genIndex(true, time);
}

std::string BufferedLogForwarder::genStatusIndex(uint64_t time) {
  return genIndex(false, time);
}

std::string BufferedLogForwarder::genIndexPrefix(bool results) {
  return index_name_ + '_' + ((results) ? 'r' : 's') + '_';
}

std::string BufferedLogForwarder::genIndex(bool results, uint64_t time) {
  if (time == 0) {
    time = getUnixTime();
  }
  return genIndexPrefix(results) + std::to_string(time) + '_' +
         std::to_string(++log_index_);
}

Status BufferedLogForwarder::addValueWithCount(const std::string& domain,
                                               const std::string& key,
                                               const std::string& value) {
  Status status = setDatabaseValue(domain, key, value);
  if (status.ok()) {
    RecursiveLock lock(count_mutex_);
    buffer_count_++;
  }
  return status;
}

Status BufferedLogForwarder::deleteValueWithCount(const std::string& domain,
                                                  const std::string& key) {
  Status status = deleteDatabaseValue(domain, key);
  if (status.ok()) {
    RecursiveLock lock(count_mutex_);
    if (buffer_count_ > 0) {
      buffer_count_--;
    }
  }
  return status;
}
} // namespace osquery
