/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/eventpublisher.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/utils/mutex.h>

#include <boost/noncopyable.hpp>

#include <map>
#include <vector>

#include <stdio.h>

namespace osquery {

/**
 * @brief Subscription context for syslog events
 *
 * Currently there is no use for the subscription context, so this class
 * remains empty.
 */

struct SyslogSubscriptionContext : public SubscriptionContext {
 private:
  friend class SyslogEventPublisher;
};

/**
 * @brief Event details for SyslogEventPublisher events
 */
struct SyslogEventContext : public EventContext {
  /**
   * @brief The syslog message tokenized into fields.
   *
   * Fields will be stripped of extra space
   */
  std::map<std::string, std::string> fields;
};

using SyslogEventContextRef = std::shared_ptr<SyslogEventContext>;
using SyslogSubscriptionContextRef = std::shared_ptr<SyslogSubscriptionContext>;

/**
 * @brief Implement a non-blocking-read of a pipe.
 *
 * The goal is to abstract a managed buffer and stream-like-object to implement
 * a version of std::getline that does not block.
 *
 * Limitations include undefined behavior (dropping the initial bytes) when a
 * line would overflow the reserved internal buffer.
 */
class NonBlockingFStream : public boost::noncopyable {
 public:
  NonBlockingFStream() {
    buffer_.reserve(2048);
    buffer_.assign(2048, 0);
  }

  explicit NonBlockingFStream(size_t capacity) {
    buffer_.reserve(capacity);
    buffer_.assign(capacity, 0);
  }

  ~NonBlockingFStream() {
    close();
  }

  /// Open for reading and writing to avoid blocking a pipe read.
  Status openReadOnly(const std::string& path);

  /// Close the managed fstream, called on destruction.
  Status close();

  /**
   * @brief Read a complete line or nothing into output.
   *
   * The output buffer will be cleared everytime. Data will only be written if
   * a complete line was dequeued from the managed stream. If too much data is
   * written and our internal buffer overflows then no data will be output.
   *
   * Overflowing the internal buffer does not break the reading. If this occurs
   * then expect a line to be truncated and only yield the max bytes.
   */
  Status getline(std::string& output);

  /// Inspect the internal offset.
  size_t offset() {
    return offset_;
  }

 private:
  /// The managed descriptor for the stream.
  int fd_{-1};

  /// Mutex for fd accesses.
  Mutex fd_mutex_;

  /// Push/pop buffer for reading a line and dequeuing.
  std::vector<char> buffer_;

  /**
   * @brief Offset into the buffer for the next read.
   *
   * If a call to getline did not find a '\n', then the next call will continue
   * to dequeue where the previous getline left off.
   */
  size_t offset_{0};

 private:
  FRIEND_TEST(SyslogTests, test_nonblockingfstream);
};

/**
 * @brief Event publisher for syslog lines forwarded through rsyslog
 *
 * This event publisher ingests JSON representations of syslog entries, and
 * publishes them to it's subscribers. In order for it to function properly,
 * rsyslog must be configured to forward JSON to a named pipe that this
 * publisher will read from.
 */
class SyslogEventPublisher
    : public EventPublisher<SyslogSubscriptionContext, SyslogEventContext> {
  DECLARE_PUBLISHER("syslog");

 public:
  Status setUp() override;

  void configure() override {}

  void tearDown() override;

  Status run() override;

 public:
  SyslogEventPublisher() : EventPublisher(), errorCount_(0), lockFd_(-1) {}

 private:
  /// Apply normal subscription to event matching logic.
  bool shouldFire(const SyslogSubscriptionContextRef& mc,
                  const SyslogEventContextRef& ec) const override;

  /**
   * @brief Create the named pipe for log forwarding.
   *
   * Attempts to properly set the permissions so that rsyslog will be able to
   * write logs to the pipe. If osquery is not running with the appropriate
   * permissions, the named pipe permissions may have to be manually edited by
   * the user in order for rsyslog to be able to write to it.
   */
  Status createPipe(const std::string& path);

  /**
   * @brief Attempt to lock the pipe for reading.
   *
   * We lock the pipe to ensure that (for example) a user opening osqueryi
   * while osqueryd is running will not try to simultaneously read from the
   * pipe and invalidate the reads from osqueryd. Only the first osquery
   * process to successfully lock the pipe will be allowed to read.
   *
   * @param path Path to the file to lock.
   * @return 0 if successful, nonzero if unable to lock the file.
   */
  Status lockPipe(const std::string& path);

  /**
   * @brief Attempt to unlock the pipe.
   */
  void unlockPipe();

  /**
   * @brief Populate the SyslogEventContext with the syslog JSON.
   *
   * Performs basic cleanup on the JSON data as it is populated into the
   * context.
   */
  static Status populateEventContext(const std::string& line,
                                     SyslogEventContextRef& ec);

  /**
   * @brief Input stream for reading from the pipe.
   */
  NonBlockingFStream readStream_;

  /**
   * @brief Counter used to shut down thread when too many errors occur.
   *
   * This counter is incremented when an error occurs, and decremented when a
   * log line is processed successfully. If it goes over kErrorThreshold, the
   * thread will return a nonzero status and stop, preventing us from flooding
   * the logs when things are in a bad state.
   */
  size_t errorCount_;

  /**
   * @brief File descriptor used to lock the pipe for reading.
   *
   * This fd should not be used for reading from the pipe, instead use
   * readStream_.
   */
  int lockFd_;

 private:
  FRIEND_TEST(SyslogTests, test_populate_event_context);
};

/**
 * Boost TokenizerFunction functor for tokenizing rsyslog CSV data
 *
 * This functor is intended to be used with boost::tokenizer in order to
 * properly parse CSV data generated by rsyslog. The default
 * boost::escaped_list_separator provided with boost::tokenizer chokes on
 * rsyslog CSV output, because rsyslog escapes " with "", and also does not
 * escape backslashes. Our implementation closely follows the one provided with
 * Boost, but allows for the idiosyncrasies of rsyslog output and simplifies
 * the implementation for our limited use case.
 */
class RsyslogCsvSeparator {
 public:
  RsyslogCsvSeparator() : last_(false) {}

  void reset() {
    last_ = false;
  }

  template <typename InputIterator, typename Token>
  bool operator()(InputIterator& next, InputIterator end, Token& tok) {
    bool in_quote = false;
    tok = Token();

    if (next == end) {
      if (last_) {
        // The last character was a comma, so we got an empty field at the end
        last_ = false;
        return true;
      } else {
        return false;
      }
    }
    last_ = false;
    for (; next != end; ++next) {
      if (*next == ',') {
        if (!in_quote) {
          ++next;
          last_ = true;
          return true;
        } else {
          tok += *next;
        }
      } else if (*next == '"') {
        auto after = next + 1;
        if (!in_quote) {
          in_quote = true;
        } else if (after != end && *after == '"') {
          // rsyslog escapes " with "", so reverse this by inserting "
          tok += "\"";
          ++next;
        } else {
          in_quote = false;
        }
      } else {
        tok += *next;
      }
    }
    return true;
  }

 private:
  bool last_;
};
} // namespace osquery
