#pragma once

#include <atomic>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <set>
#include <thread>
#include <unordered_map>
#include <vector>

#include <libaudit.h>

namespace osquery {

/// Netlink status, used by AuditNetlink::acquireHandle()
enum class NetlinkStatus { ActiveMutable, ActiveImmutable, Disabled, Error };

/// Subscription handle to be used with AuditNetlink::getEvents()
typedef std::uint32_t NetlinkSubscriptionHandle;

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

/// The subscriber context used by the AuditNetlink class to store the audit
/// event records.
struct AuditNetlinkSubscriberContext final {
  /// This queue contains unprocessed events, waiting for a
  /// AuditNetlink::getEvents() call to finalize them.
  std::vector<AuditEventRecord> queue;

  /// Queue mutex.
  std::mutex queue_mutex;
};

class AuditNetlink final {
  /// This is the set of rules we have applied when configuring the service.
  /// This is also what we need to remove when exiting.
  std::vector<audit_rule_data> installed_rule_list_;

  /// The syscalls we are listening for
  std::set<int> monitored_syscall_list_;

  //
  // Common thread data
  //

  /// Netlink handle.
  int audit_netlink_handle_{-1};

  /// True if the netlink class has been initialized.
  bool initialized_{false};

  /// Initialization mutex
  std::mutex initialization_mutex_;

  /// This value is used to generate subscription handles.
  NetlinkSubscriptionHandle handle_generator_{0};

  /// Mutex that guards the subscriber list.
  std::mutex subscribers_mutex_;

  /// How many subscribers are receiving events; it is updated each time
  /// ::subscribe()/::unsubscribe() are called.
  std::atomic<std::size_t> subscriber_count_{0};

  /// Subscriber map.
  std::unordered_map<NetlinkSubscriptionHandle, AuditNetlinkSubscriberContext>
      subscribers_;

  /// Set to true by ::terminate() when the thread should exit.
  std::atomic<bool> terminate_threads_{false};

  /// Used to wake up the thread that processes the raw audit records
  std::condition_variable raw_records_pending_;

  /// When set to true, the audit handle is (re)acquired
  std::atomic_bool acquire_netlink_handle_{true};

  //
  // Primary thread (recvThread)
  //

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

  //
  // Secondary thread (processThread)
  //

  /// The thread that processes the audit events
  std::unique_ptr<std::thread> processing_thread_;

 public:
  static AuditNetlink& getInstance();
  ~AuditNetlink();

  /// Creates a subscription context and returns a handle that can be used with
  /// ::getEvents().
  NetlinkSubscriptionHandle subscribe() noexcept;

  /// Destroyes the subscription context associated with the given handle.
  void unsubscribe(NetlinkSubscriptionHandle handle) noexcept;

  /// Prepares the raw audit event records stored in the given subscriber
  /// context and returns them to the caller.
  std::vector<AuditEventRecord> getEvents(
      NetlinkSubscriptionHandle handle) noexcept;

  /// Parses an audit_reply structure into an AuditEventRecord object
  static bool ParseAuditReply(const audit_reply& reply,
                              AuditEventRecord& event_record) noexcept;

 private:
  AuditNetlink();

  /// Starts the event receiver thread.
  bool start() noexcept;

  /// Terminates the thread receiving the events
  void terminate() noexcept;

  /// This is the entry point for the thread that receives the netlink events.
  bool recvThread() noexcept;

  /// This is the entry point for the thread that processes the netlink events.
  bool processThread() noexcept;

  /// Reads as many audit event records as possible before returning.
  bool acquireMessages() noexcept;

  /// Configures the audit service and applies required rules
  bool configureAuditService() noexcept;

  /// Removes the rules that we have applied
  void restoreAuditServiceConfiguration() noexcept;

  /// (Re)acquire the netlink handle.
  NetlinkStatus acquireHandle() noexcept;

  AuditNetlink(const AuditNetlink&) = delete;
  AuditNetlink& operator=(const AuditNetlink&) = delete;
};
}
