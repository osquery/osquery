/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <libaudit.h>

#include <atomic>
#include <condition_variable>
#include <future>
#include <map>
#include <memory>
#include <set>
#include <thread>
#include <unordered_map>
#include <vector>

#include <boost/algorithm/hex.hpp>

namespace osquery {

/// Netlink status, used by AuditNetlink::acquireHandle()
enum class NetlinkStatus { ActiveMutable, ActiveImmutable, Disabled, Error };

/// Contains an audit_rule_data structure
using AuditRuleDataObject = std::vector<std::uint8_t>;

/// A single, prepared audit event record.
struct AuditEventRecord final {
  /// Record type (i.e.: AUDIT_SYSCALL, AUDIT_PATH, ...)
  int type;

  /// Event time.
  unsigned long int time;

  /// Audit event id that owns this record. Remember: PRIMARY KEY(id, timestamp)
  std::string audit_id;

  /// The field list for this record.
  std::map<std::string, std::string> fields;
};

class AuditdNetlink final : private boost::noncopyable {
 public:
  AuditdNetlink();
  ~AuditdNetlink();

  /// Prepares the raw audit event records stored in the given context.
  std::vector<AuditEventRecord> getEvents() noexcept;

  /// Parses an audit_reply structure into an AuditEventRecord object
  static bool ParseAuditReply(const audit_reply& reply,
                              AuditEventRecord& event_record) noexcept;

  /// Adjusts the internal pointers of the audit_reply object
  static void AdjustAuditReply(audit_reply& reply) noexcept;

 private:
  /// This is the entry point for the thread that receives the netlink events.
  bool recvThread() noexcept;

  /// This is the entry point for the thread that processes the netlink events.
  bool processThread() noexcept;

  /// Reads as many audit event records as possible before returning.
  bool acquireMessages() noexcept;

  /// Configures the audit service and applies required rules
  bool configureAuditService() noexcept;

  /// Clears out the audit configuration
  bool clearAuditConfiguration() noexcept;

  /// Deletes the given audit rule
  bool deleteAuditRule(const AuditRuleDataObject& rule_object);

  /// Removes the rules that we have applied
  void restoreAuditServiceConfiguration() noexcept;

  /// (Re)acquire the netlink handle.
  NetlinkStatus acquireHandle() noexcept;

 private:
  /// The set of rules we applied (and that we'll uninstall when exiting)
  std::vector<audit_rule_data> installed_rule_list_;

  /// The syscalls we are listening for
  std::set<int> monitored_syscall_list_;

  /// Netlink handle.
  int audit_netlink_handle_{-1};

  /// Set to true by ::terminate() when the thread should exit.
  std::atomic<bool> terminate_threads_{false};

  /// Used to wake up the thread that processes the raw audit records
  std::condition_variable proc_thread_cv_;

  /// When set to true, the audit handle is (re)acquired
  std::atomic_bool acquire_netlink_handle_{true};

  /// The thread that receives the audit events from the netlink.
  std::unique_ptr<std::thread> recv_thread_;

  /// Unprocessed audit records
  std::vector<audit_reply> raw_audit_record_list_;
  static_assert(
      std::is_move_constructible<decltype(raw_audit_record_list_)>::value,
      "not move constructible");

  /// Mutex for the list of unprocessed records
  std::mutex raw_audit_record_list_mutex_;

  /// Read buffer used when receiving events from the netlink
  std::vector<audit_reply> read_buffer_;

  /// The thread that processes the audit events
  std::unique_ptr<std::thread> processing_thread_;

  /// This queue contains processed events
  std::vector<AuditEventRecord> event_queue_;

  /// Processed events queue mutex.
  std::mutex event_queue_mutex_;

  /// Processed events condition variable
  std::condition_variable event_queue_cv_;
};

/// Handle quote and hex-encoded audit field content.
inline std::string DecodeAuditPathValues(const std::string& s) {
  if (s.size() > 1 && s[0] == '"') {
    return s.substr(1, s.size() - 2);
  }

  try {
    return boost::algorithm::unhex(s);
  } catch (const boost::algorithm::hex_decode_error& e) {
    return s;
  }
}
}
