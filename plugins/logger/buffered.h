/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <osquery/core/plugins/logger.h>
#include <osquery/dispatcher/dispatcher.h>

namespace osquery {

/// Iterate through a vector, yielding during high utilization
inline void iterate(std::vector<std::string>& input,
                    std::function<void(std::string&)> predicate) {
  // Since there are no 'multi-do' APIs, keep a count of consecutive actions.
  // This count allows us to sleep the thread to prevent utilization thrash.
  size_t count = 0;
  for (auto& item : input) {
    // The predicate is provided a mutable string.
    // It may choose to clear/move the data.
    predicate(item);
    if (++count % 100 == 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }
}

/**
 * @brief A log forwarder thread flushing database-buffered logs.
 *
 * This is a base class intended to provide reliable buffering and sending of
 * status and result logs. Subclasses take advantage of this reliable sending
 * logic, and implement their own methods for actually sending logs.
 *
 * Subclasses must define the send() method, and if a subclass overrides
 * setUp(), it **MUST** call this base class setUp() from that method.
 */
class BufferedLogForwarder : public InternalRunnable {
 protected:
  static const std::chrono::seconds kLogPeriod;
  static const uint64_t kMaxLogLines;

 protected:
  // These constructors are made available for subclasses to use, but
  // subclasses should expose appropriate constructors to their users.
  explicit BufferedLogForwarder(const std::string& service_name,
                                const std::string& name)
      : InternalRunnable(service_name),
        log_period_(kLogPeriod),
        max_log_lines_(kMaxLogLines),
        index_name_(name) {}

  template <class Rep, class Period>
  explicit BufferedLogForwarder(
      const std::string& service_name,
      const std::string& name,
      const std::chrono::duration<Rep, Period>& log_period)
      : InternalRunnable(service_name),
        log_period_(
            std::chrono::duration_cast<std::chrono::seconds>(log_period)),
        max_log_lines_(kMaxLogLines),
        index_name_(name) {}

  template <class Rep, class Period>
  explicit BufferedLogForwarder(
      const std::string& service_name,
      const std::string& name,
      const std::chrono::duration<Rep, Period>& log_period,
      uint64_t max_log_lines)
      : InternalRunnable(service_name),
        log_period_(
            std::chrono::duration_cast<std::chrono::seconds>(log_period)),
        max_log_lines_(max_log_lines),
        index_name_(name) {}

 public:
  /// A simple wait lock, and flush based on settings.
  void start() override;

  /**
   * @brief Set up the forwarder. May be used to init remote clients, etc.
   *
   * This base class setUp() **MUST** be called by subclasses of
   * BufferedLogForwarder in order to properly initialize the buffer count.
  */
  virtual Status setUp();

  /**
   * @brief Log a results string
   *
   * Writes the result string to the backing store for buffering, but *does
   * not* actually send the string. The string will only be sent when check()
   * runs and uses send() to send it.
   *
   * @param s Results string to log
   */
  Status logString(const std::string& s, uint64_t time = 0);

  /**
   * @brief Log a vector of status lines
   *
   * Decorates the status lines before writing to the backing store for
   * buffering . *Does not* actually send the logs. The logs will only be sent
   * when check() runs and uses send() to send them.
   *
   * @param log Vector of status lines to log
   */
  Status logStatus(const std::vector<StatusLogLine>& log, uint64_t time = 0);

 protected:
  /**
   * @brief Send labeled result logs.
   *
   * The log_data provided to send must be mutable.
   * To optimize for smaller memory, this will be moved into place within the
   * constructed property tree before sending.
   */
  virtual Status send(std::vector<std::string>& log_data,
                      const std::string& log_type) = 0;

  /**
   * @brief Check for new logs and send.
   *
   * Scan the logs domain for up to max_log_lines_ log lines.
   * Sort those lines into status and request types then forward (send) each
   * set. On success, clear the data and indexes. Calls purge upon completion.
   */
  void check();

  /**
   * @brief Purge the oldest logs, if the max is exceeded
   *
   * Uses the buffered_log_max flag to determine the maximum number of buffered
   * logs. If this number is exceeded, the logs with the oldest timestamp are
   * purged. Order of purging for logs with the same timestamp is undefined.
   */
  void purge();

 protected:
  /// Return whether the string is a result index
  bool isResultIndex(const std::string& index);

  /// Return whether the string is a status index
  bool isStatusIndex(const std::string& index);

 private:
  /// Helper for isResultIndex/isStatusIndex
  bool isIndex(const std::string& index, bool results);

 protected:
  /// Generate a result index string to use with the backing store
  std::string genResultIndex(uint64_t time = 0);

  /// Generate a status index string to use with the backing store
  std::string genStatusIndex(uint64_t time = 0);

 private:
  std::string genIndexPrefix(bool results);

  std::string genIndex(bool results, uint64_t time = 0);

  /**
   * @brief Add a database value while maintaining count
   *
   */
  Status addValueWithCount(const std::string& domain,
                           const std::string& key,
                           const std::string& value);

  /**
   * @brief Delete a database value while maintaining count
   *
   */
  Status deleteValueWithCount(const std::string& domain,
                              const std::string& key);

 protected:
  /// Seconds between flushing logs
  std::chrono::seconds log_period_;

  /// Max number of logs to flush per check
  uint64_t max_log_lines_;

  /**
   * @brief Name to use in index
   *
   * This name is used so that loggers of different types that are operating
   * simultaneously can separately maintain their buffer of logs in the backing
   * store.
   */
  std::string index_name_;

 private:
  /// Hold an incrementing index for buffering logs
  std::atomic<size_t> log_index_{0};

  /// Stores the count of buffered logs
  unsigned long long int buffer_count_{0};

  /// Protects the count of buffered logs
  RecursiveMutex count_mutex_;
};
}
