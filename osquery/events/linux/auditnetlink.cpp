#include "osquery/events/linux/auditnetlink.h"
#include "osquery/core/conversions.h"

#include <osquery/flags.h>
#include <osquery/logger.h>

#include <chrono>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/filesystem.hpp>
#include <boost/utility/string_ref.hpp>

#include <linux/audit.h>
#include <poll.h>
#include <sys/types.h>
#include <unistd.h>

/** \todo check for the AUDIT_GET event and persist

  if (static_cast<pid_t>(status_.pid) != getpid()) {
    if (control_ && status_.pid != 0) {
      VLOG(1) << "Audit control lost to pid: " << status_.pid;
      // This process has lost control of audit.
      // The initial request for control was made during setup.
      control_ = false;
    }

    if (FLAGS_audit_persist && !FLAGS_disable_audit && !immutable_) {
      VLOG(1) << "Persisting audit control";
      audit_set_pid(handle_, getpid(), WAIT_NO);
      control_ = true;
    }
  }

  // Only apply a cool down if the reply request failed.
  return Status(0, "OK");
 */

/** \todo dedup
  if (ec->type >= AUDIT_FIRST_USER_MSG && ec->type <= AUDIT_LAST_USER_MSG) {
    if (!checkUserCache(ec->audit_id)) {
      return false;
    }
  }
 */

namespace osquery {
/// The audit subsystem may have a performance impact on the system.
FLAG(bool,
     disable_audit,
     true,
     "Disable receiving events from the audit subsystem");

/// Control the audit subsystem by electing to be the single process sink.
FLAG(bool, audit_persist, true, "Attempt to retain control of audit");

/// Control the audit subsystem by allowing subscriptions to apply rules.
FLAG(bool,
     audit_allow_config,
     false,
     "Allow the audit publisher to change auditing configuration");

/// Audit debugger helper
HIDDEN_FLAG(bool, audit_debug, false, "Debug Linux audit messages");

enum AuditStatus {
  AUDIT_DISABLED = 0,
  AUDIT_ENABLED = 1,
  AUDIT_IMMUTABLE = 2,
};

AuditNetlink& AuditNetlink::getInstance() {
  static AuditNetlink instance;
  return instance;
}

AuditNetlink::~AuditNetlink() {
  terminate();
  thread_->join();

  audit_close(audit_netlink_handle_);
}

bool AuditNetlink::start() noexcept {
  try {
    std::packaged_task<bool(AuditNetlink&)> thread_task(
        std::bind(&AuditNetlink::thread, this));

    thread_result_ = thread_task.get_future().share();
    thread_.reset(new std::thread(std::move(thread_task), std::ref(*this)));

    initialized_ = true;
    return true;

  } catch (const std::bad_alloc&) {
    return false;
  }
}

NetlinkSubscriptionHandle AuditNetlink::subscribe() noexcept {
  if (!initialized_) {
    if (!start()) {
      VLOG(1) << "Failed to initialize the AuditNetlink classs";
      return 0;
    }
  }

  std::lock_guard<std::mutex> lock(subscribers_mutex_);

  auto new_handle = ++handle_generator_;
  subscribers_[new_handle];

  subscriber_count_ = subscribers_.size();
  return new_handle;
}

void AuditNetlink::unsubscribe(NetlinkSubscriptionHandle handle) noexcept {
  std::lock_guard<std::mutex> lock(subscribers_mutex_);

  auto it = subscribers_.find(handle);
  if (it == subscribers_.end())
    return;

  subscribers_.erase(it);

  subscriber_count_ = subscribers_.size();
}

void AuditNetlink::terminate() noexcept {
  terminate_thread_ = true;
}
std::vector<AuditEventRecord> AuditNetlink::getEvents(
    NetlinkSubscriptionHandle handle) noexcept {
  std::vector<audit_reply> audit_reply_queue;

  {
    std::lock_guard<std::mutex> subscriber_list_lock(subscribers_mutex_);

    auto subscriber_it = subscribers_.find(handle);
    if (subscriber_it == subscribers_.end())
      return std::vector<AuditEventRecord>();

    auto& context = subscriber_it->second;

    {
      std::lock_guard<std::mutex> queue_lock(context.queue_mutex);

      audit_reply_queue = std::move(context.queue);
      context.queue.clear();
    }
  }

  std::vector<AuditEventRecord> audit_event_record_queue;

  for (const audit_reply& reply : audit_reply_queue) {
    bool dispatch_message = false;

    switch (reply.type) {
    case NLMSG_NOOP:
    case NLMSG_DONE:
    case NLMSG_ERROR:
    case AUDIT_LIST_RULES:
    case AUDIT_SECCOMP:
    case AUDIT_GET:
    case (AUDIT_GET + 1)...(AUDIT_LIST_RULES - 1):
    case (AUDIT_LIST_RULES + 1)...(AUDIT_FIRST_USER_MSG - 1):
    case AUDIT_DAEMON_START ... AUDIT_DAEMON_CONFIG: // 1200 - 1203
    case AUDIT_CONFIG_CHANGE:
      break;

    case AUDIT_FIRST_USER_MSG ... AUDIT_LAST_USER_MSG:
    case AUDIT_SYSCALL: // 1300
    case AUDIT_CWD: // 1307
    case AUDIT_PATH: // 1302
    case AUDIT_EXECVE: // // 1309 (execve arguments).
    default:
      dispatch_message = true;
      break;
    }

    if (!dispatch_message)
      continue;

    AuditEventRecord audit_event_record = {};
    audit_event_record.type = reply.type;

    // Tokenize the message.
    boost::string_ref message_view(reply.message, reply.len);
    auto preamble_end = message_view.find("): ");
    if (preamble_end == std::string::npos) {
      VLOG(1) << "Malformed message received";
      continue;
    }

    safeStrtoul(
        std::string(message_view.substr(6, 10)), 10, audit_event_record.time);
    safeStrtoul(std::string(message_view.substr(21, preamble_end - 21)),
                10,
                audit_event_record.audit_id);
    boost::string_ref field_view(message_view.substr(preamble_end + 3));

    // The linear search will construct series of key value pairs.
    std::string key, value;
    key.reserve(20);
    value.reserve(256);

    // There are several ways of representing value data (enclosed strings,
    // etc).
    bool found_assignment{false}, found_enclose{false};
    for (const auto& c : field_view) {
      // Iterate over each character in the audit message.
      if ((found_enclose && c == '"') || (!found_enclose && c == ' ')) {
        if (c == '"') {
          value += c;
        }

        // This is a terminating sequence, the end of an enclosure or space tok.
        if (!key.empty()) {
          // Multiple space tokens are supported.
          audit_event_record.fields.emplace(
              std::make_pair(std::move(key), std::move(value)));
        }

        found_enclose = false;
        found_assignment = false;
        key.clear();
        value.clear();

      } else if (!found_assignment && c == ' ') {
        // A field tokenizer.

      } else if (found_assignment) {
        // Enclosure sequences appear immediately following assignment.
        if (c == '"') {
          found_enclose = true;
        }

        value += c;

      } else if (c == '=') {
        found_assignment = true;

      } else {
        key += c;
      }
    }

    // Last step, if there was no trailing tokenizer.
    if (!key.empty()) {
      audit_event_record.fields.emplace(
          std::make_pair(std::move(key), std::move(value)));
    }

    if (FLAGS_audit_debug) {
      fprintf(stdout,
              "%zu: (%d) ",
              audit_event_record.audit_id,
              audit_event_record.type);
      for (const auto& f : audit_event_record.fields) {
        fprintf(stdout, "%s=%s ", f.first.c_str(), f.second.c_str());
      }
      fprintf(stdout, "\n");
    }

    audit_event_record_queue.push_back(audit_event_record);
  }

  return audit_event_record_queue;
}

AuditNetlink::AuditNetlink() {}

bool AuditNetlink::thread() noexcept {
  std::uint8_t requests_to_next_sanity_check = 0;

  while (!terminate_thread_) {
    if (subscriber_count_ == 0) {
      std::this_thread::sleep_for(std::chrono::seconds(5));
      continue;
    }

    if (requests_to_next_sanity_check == 0) {
      requests_to_next_sanity_check = 10;

      NetlinkStatus netlink_status = acquireHandle();
      switch (netlink_status) {
      case NetlinkStatus::Disabled:
      case NetlinkStatus::Error: {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        break;
      }

      case NetlinkStatus::ActiveMutable:
      case NetlinkStatus::ActiveImmutable:
        break;
      }
    }

    if (!acquireMessages()) {
      requests_to_next_sanity_check = 0;
      continue;
    }

    --requests_to_next_sanity_check;
  }

  return true;
}

bool AuditNetlink::acquireMessages() noexcept {
  pollfd fds[] = {{audit_netlink_handle_, POLLIN, 0}};

  struct sockaddr_nl nladdr = {};
  socklen_t nladdrlen = sizeof(nladdr);

  std::vector<audit_reply> reply_list;
  bool success = false;

  for (int i = 0; i < 32; i++) {
    errno = 0;
    if (::poll(fds, 1, 0) <= 0) {
      if (errno == EINTR || errno == EAGAIN) {
        success = true;
      }

      break;
    }

    if (!(fds[0].revents & POLLIN)) {
      success = true;
      break;
    }

    audit_reply reply = {};
    int len = recvfrom(audit_netlink_handle_,
                       &reply.msg,
                       sizeof(reply.msg),
                       0,
                       reinterpret_cast<struct sockaddr*>(&nladdr),
                       &nladdrlen);

    /// \todo Handle the following errors!
    if (len < 0) {
      VLOG(1) << "Failed to receive data from the audit netlink";
      success = false;
      break;
    }

    if (nladdrlen != sizeof(nladdr)) {
      VLOG(1) << "Protocol error";
      success = false;
      break;
    }

    if (nladdr.nl_pid) {
      VLOG(1) << "Invalid netlink endpoint";
      success = false;
      break;
    }

    // Adjust the reply
    reply.type = reply.msg.nlh.nlmsg_type;
    reply.len = reply.msg.nlh.nlmsg_len;
    reply.nlh = &reply.msg.nlh;

    reply.status = nullptr;
    reply.ruledata = nullptr;
    reply.login = nullptr;
    reply.message = nullptr;
    reply.error = nullptr;
    reply.signal_info = nullptr;
    reply.conf = nullptr;

    if (!NLMSG_OK(reply.nlh, static_cast<unsigned int>(len))) {
      if (len == sizeof(reply.msg)) {
        VLOG(1) << "NLMSG_OK failed (EFBIG)";
      } else {
        VLOG(1) << "NLMSG_OK failed (EBADE)";
      }

      success = false;
      break;
    }

    switch (reply.type) {
    case AUDIT_GET:
      reply.status = static_cast<struct audit_status*>(NLMSG_DATA(reply.nlh));
      break;

    case AUDIT_LIST_RULES:
      reply.ruledata =
          static_cast<struct audit_rule_data*>(NLMSG_DATA(reply.nlh));
      break;

    case AUDIT_USER:
    case AUDIT_LOGIN:
    case AUDIT_KERNEL:
    case AUDIT_FIRST_USER_MSG ... AUDIT_LAST_USER_MSG:
    case AUDIT_FIRST_USER_MSG2 ... AUDIT_LAST_USER_MSG2:
    case AUDIT_FIRST_EVENT ... AUDIT_INTEGRITY_LAST_MSG:
      reply.message = static_cast<char*>(NLMSG_DATA(reply.nlh));
      break;

    default:
      break;
    }

    reply_list.push_back(reply);
  }

  if (!reply_list.empty()) {
    std::lock_guard<std::mutex> subscriber_list_lock(subscribers_mutex_);

    for (auto& subscriber_descriptor : subscribers_) {
      auto& subscriber_context = subscriber_descriptor.second;

      std::lock_guard<std::mutex> queue_lock(subscriber_context.queue_mutex);
      subscriber_context.queue.insert(
          subscriber_context.queue.end(), reply_list.begin(), reply_list.end());
    }
  }

  return success;
}

NetlinkStatus AuditNetlink::acquireHandle() noexcept {
  if (FLAGS_disable_audit) {
    return NetlinkStatus::Disabled;
  }

  audit_netlink_handle_ = audit_open();
  if (audit_netlink_handle_ <= 0) {
    return NetlinkStatus::Error;
  }

  if (FLAGS_audit_allow_config) {
    audit_set_enabled(audit_netlink_handle_, AUDIT_ENABLED);
  }

  audit_request_status(audit_netlink_handle_);

  auto enabled = audit_is_enabled(audit_netlink_handle_);
  if (enabled == AUDIT_IMMUTABLE || getuid() != 0 ||
      !FLAGS_audit_allow_config) {
    return NetlinkStatus::ActiveImmutable;

  } else if (enabled != AUDIT_ENABLED) {
    audit_close(audit_netlink_handle_);
    return NetlinkStatus::Error;
  }

  if (audit_set_pid(audit_netlink_handle_, getpid(), WAIT_YES) < 0) {
    audit_close(audit_netlink_handle_);
    return NetlinkStatus::Error;
  }

  // Want to set a min sane buffer and maximum number of events/second min.
  // This is normally controlled through the audit config, but we must
  // enforce sane minimums: -b 8192 -e 100
  audit_set_backlog_wait_time(audit_netlink_handle_, 1);
  audit_set_backlog_limit(audit_netlink_handle_, 1024);
  audit_set_failure(audit_netlink_handle_, AUDIT_FAIL_SILENT);

  // Request only the highest priority of audit status messages.
  set_aumessage_mode(MSG_QUIET, DBG_NO);

  return NetlinkStatus::ActiveMutable;
}
}