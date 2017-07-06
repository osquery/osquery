#pragma once

#include <atomic>
#include <functional>
#include <future>
#include <map>
#include <memory>
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

  /// Audit event id that owns this record.
  unsigned long int audit_id;

  /// The field list for this record.
  std::map<std::string, std::string> fields;
};

/// The subscriber context used by the AuditNetlink class to store the audit
/// event records.
struct AuditNetlinkSubscriberContext final {
  /// This queue contains unprocessed events, waiting for a
  /// AuditNetlink::getEvents() call to finalize them.
  std::vector<audit_reply> queue;

  /// Queue mutex.
  std::mutex queue_mutex;
};

class AuditNetlink final {
  /// Netlink handle.
  int audit_netlink_handle_{0};

  /// True if the netlink class has been initialized.
  bool initialized_{false};

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

  /// The thread that receives and pre-process the audit events.
  std::unique_ptr<std::thread> thread_;

  /// The thread exit code.
  std::shared_future<bool> thread_result_;

  /// Set to true by ::terminate() when the thread should exit.
  std::atomic<bool> terminate_thread_{false};

 public:
  static AuditNetlink& getInstance();
  ~AuditNetlink();

  /// Creates a subscription context and returns a handle that can be used with
  /// ::getEvents().
  NetlinkSubscriptionHandle subscribe() noexcept;

  /// Destroyes the subscription context associated with the given handle.
  void unsubscribe(NetlinkSubscriptionHandle handle) noexcept;

  /// Asks the event receiver thread to terminate
  void terminate() noexcept;

  /// Prepares the raw audit event records stored in the given subscriber
  /// context and returns them to the caller.
  std::vector<AuditEventRecord> getEvents(
      NetlinkSubscriptionHandle handle) noexcept;

 private:
  AuditNetlink();

  /// Starts the event receiver thread.
  bool start() noexcept;

  /// This is the entry point for the event receive thread.
  bool thread() noexcept;

  /// Reads as many audit event records as possible before returning.
  bool acquireMessages() noexcept;

  /// (Re)acquire the netlink handle.
  NetlinkStatus acquireHandle() noexcept;

  AuditNetlink(const AuditNetlink&) = delete;
  AuditNetlink& operator=(const AuditNetlink&) = delete;
};
}
