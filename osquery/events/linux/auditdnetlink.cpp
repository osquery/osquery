/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <linux/audit.h>
#include <poll.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <iostream>

#include <boost/utility/string_ref.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/events/linux/auditdnetlink.h"
#include "osquery/tables/events/linux/auditd_fim_events.h"
#include "osquery/tables/events/linux/process_events.h"
#include "osquery/tables/events/linux/socket_events.h"

namespace {
bool ShouldHandle(const audit_reply& reply) noexcept {
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
    return false;

  default:
    return true;
  }
}
}

namespace osquery {
/// Control the audit subsystem by electing to be the single process sink.
FLAG(bool, audit_persist, true, "Attempt to retain control of audit");

/// Audit debugger helper
HIDDEN_FLAG(bool, audit_debug, false, "Debug Linux audit messages");

/// Control the audit subsystem by allowing subscriptions to apply rules.
FLAG(bool,
     audit_allow_config,
     false,
     "Allow the audit publisher to change auditing configuration");

/// Always uninstall all the audit rules that osquery uses when exiting
FLAG(bool,
     audit_force_unconfigure,
     false,
     "Always uninstall all rules, regardless of whether they were already "
     "installed or not");

/// Forces osquery to remove all rules upon startup
FLAG(bool,
     audit_force_reconfigure,
     false,
     "Configure the audit subsystem from scratch");

// External flags; they are used to determine which rules needs to be installed
DECLARE_bool(audit_allow_fim_events);
DECLARE_bool(audit_allow_process_events);
DECLARE_bool(audit_allow_sockets);
DECLARE_bool(audit_allow_user_events);

enum AuditStatus {
  AUDIT_DISABLED = 0,
  AUDIT_ENABLED = 1,
  AUDIT_IMMUTABLE = 2,
};

AuditdNetlink::AuditdNetlink() {
  // Allocate the read buffer before we start the threads
  const size_t read_buffer_size = 4096;

  read_buffer_.resize(read_buffer_size);
  if (read_buffer_.size() != read_buffer_size) {
    VLOG(1) << "Failed to allocate the audit netlink read buffer";
    throw std::bad_alloc();
  }

  // Start the reading thread
  std::packaged_task<bool(AuditdNetlink&)> recv_thread_task(
      std::bind(&AuditdNetlink::recvThread, this));

  recv_thread_.reset(
      new std::thread(std::move(recv_thread_task), std::ref(*this)));

  // Start the processing thread
  std::packaged_task<bool(AuditdNetlink&)> processing_thread_task(
      std::bind(&AuditdNetlink::processThread, this));

  processing_thread_.reset(
      new std::thread(std::move(processing_thread_task), std::ref(*this)));
}

AuditdNetlink::~AuditdNetlink() {
  terminate_threads_ = true;

  processing_thread_->join();
  recv_thread_->join();
}

std::vector<AuditEventRecord> AuditdNetlink::getEvents() noexcept {
  std::vector<AuditEventRecord> record_list;

  {
    std::unique_lock<std::mutex> queue_lock(event_queue_mutex_);

    if (event_queue_cv_.wait_for(queue_lock, std::chrono::seconds(5)) ==
        std::cv_status::no_timeout) {
      record_list = std::move(event_queue_);
      event_queue_.clear();
    }
  }

  return record_list;
}

bool AuditdNetlink::ParseAuditReply(const audit_reply& reply,
                                    AuditEventRecord& event_record) noexcept {
  event_record = {};

  if (FLAGS_audit_debug) {
    std::cout << reply.type << ", " << std::string(reply.message, reply.len)
              << std::endl;
  }

  // Tokenize the message.
  event_record.type = reply.type;
  boost::string_ref message_view(reply.message,
                                 static_cast<unsigned int>(reply.len));

  auto preamble_end = message_view.find("): ");
  if (preamble_end == std::string::npos) {
    return false;
  }

  safeStrtoul(message_view.substr(6, 10).to_string(), 10, event_record.time);
  event_record.audit_id = message_view.substr(6, preamble_end - 6).to_string();
  boost::string_ref field_view(message_view.substr(preamble_end + 3));

  // The linear search will construct series of key value pairs.
  std::string key, value;
  key.reserve(20);
  value.reserve(256);

  // There are several ways of representing value data (enclosed strings,
  // etc).
  bool found_assignment{false};
  bool found_enclose{false};

  for (const auto& c : field_view) {
    // Iterate over each character in the audit message.
    if ((found_enclose && c == '"') || (!found_enclose && c == ' ')) {
      if (c == '"') {
        value += c;
      }

      // This is a terminating sequence, the end of an enclosure or space
      // tok.
      if (!key.empty()) {
        // Multiple space tokens are supported.
        event_record.fields.emplace(
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
    event_record.fields.emplace(
        std::make_pair(std::move(key), std::move(value)));
  }

  return true;
}

void AuditdNetlink::AdjustAuditReply(audit_reply& reply) noexcept {
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

  switch (reply.type) {
  case NLMSG_ERROR: {
    reply.error = static_cast<struct nlmsgerr*>(NLMSG_DATA(reply.nlh));
    break;
  }

  case AUDIT_LIST_RULES: {
    reply.ruledata =
        static_cast<struct audit_rule_data*>(NLMSG_DATA(reply.nlh));
    break;
  }

  case AUDIT_USER:
  case AUDIT_LOGIN:
  case AUDIT_KERNEL:
  case AUDIT_FIRST_USER_MSG ... AUDIT_LAST_USER_MSG:
  case AUDIT_FIRST_USER_MSG2 ... AUDIT_LAST_USER_MSG2:
  case AUDIT_FIRST_EVENT ... AUDIT_INTEGRITY_LAST_MSG: {
    reply.message = static_cast<char*>(NLMSG_DATA(reply.nlh));
    break;
  }

  case AUDIT_SIGNAL_INFO: {
    reply.signal_info = static_cast<audit_sig_info*>(NLMSG_DATA(reply.nlh));
    break;
  }

  default:
    break;
  }
}

bool AuditdNetlink::recvThread() noexcept {
  acquire_netlink_handle_ = true;

  int counter_to_next_status_request = 0;
  const int status_request_countdown = 1000;

  while (!terminate_threads_) {
    if (acquire_netlink_handle_) {
      if (FLAGS_audit_debug) {
        std::cout << "(re)acquiring the audit handle.." << std::endl;
      }

      NetlinkStatus netlink_status = acquireHandle();

      if (netlink_status == NetlinkStatus::Disabled ||
          netlink_status == NetlinkStatus::Error) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        continue;
      }

      acquire_netlink_handle_ = false;
      counter_to_next_status_request = status_request_countdown;
    }

    if (counter_to_next_status_request == 0) {
      errno = 0;

      if (audit_request_status(audit_netlink_handle_) <= 0) {
        if (errno == ENOBUFS) {
          VLOG(1) << "Warning: Failed to request audit status (ENOBUFS). "
                     "Retrying again later...";

        } else {
          VLOG(1) << "Error: Failed to request audit status. Requesting a "
                     "handle reset";

          acquire_netlink_handle_ = true;
        }
      }

      counter_to_next_status_request = status_request_countdown;
    } else {
      --counter_to_next_status_request;
    }

    if (!acquireMessages()) {
      acquire_netlink_handle_ = true;
      continue;
    }
  }

  proc_thread_cv_.notify_one();
  restoreAuditServiceConfiguration();

  audit_close(audit_netlink_handle_);
  audit_netlink_handle_ = -1;

  return true;
}

bool AuditdNetlink::processThread() noexcept {
  while (!terminate_threads_) {
    std::vector<audit_reply> queue;

    {
      std::unique_lock<std::mutex> lock(raw_audit_record_list_mutex_);

      while (raw_audit_record_list_.empty() && !terminate_threads_) {
        proc_thread_cv_.wait(lock);
      }

      queue = std::move(raw_audit_record_list_);
      raw_audit_record_list_.clear();
    }

    std::vector<AuditEventRecord> audit_event_record_queue;

    for (auto& reply : queue) {
      AdjustAuditReply(reply);

      // This record carries the process id of the controlling daemon; in case
      // we lost control of the audit service, we are going to request a reset
      // as soon as we finish processing the pending queue
      if (reply.type == AUDIT_GET) {
        reply.status = static_cast<struct audit_status*>(NLMSG_DATA(reply.nlh));
        auto new_pid = static_cast<pid_t>(reply.status->pid);

        if (new_pid != getpid()) {
          VLOG(1) << "Audit control lost to pid: " << new_pid;

          if (FLAGS_audit_persist) {
            VLOG(1) << "Attempting to reacquire control of the audit service";
            acquire_netlink_handle_ = true;
          }
        }

        continue;
      }

      // We are not interested in all messages; only get the ones related to
      // user events and syscalls
      if (!ShouldHandle(reply)) {
        continue;
      }

      // Parse the audit record body and store it into our queue
      AuditEventRecord audit_event_record = {};
      if (!ParseAuditReply(reply, audit_event_record)) {
        VLOG(1) << "Malformed audit record received";
        continue;
      }

      audit_event_record_queue.push_back(audit_event_record);
    }

    // Save the new records and notify the reader
    if (!audit_event_record_queue.empty()) {
      std::lock_guard<std::mutex> queue_lock(event_queue_mutex_);

      event_queue_.reserve(event_queue_.size() +
                           audit_event_record_queue.size());
      event_queue_.insert(event_queue_.end(),
                          audit_event_record_queue.begin(),
                          audit_event_record_queue.end());

      event_queue_cv_.notify_all();
    }

    queue.clear();
    audit_event_record_queue.clear();
  }

  return true;
}

bool AuditdNetlink::acquireMessages() noexcept {
  pollfd fds[] = {{audit_netlink_handle_, POLLIN, 0}};

  struct sockaddr_nl nladdr = {};
  socklen_t nladdrlen = sizeof(nladdr);

  bool reset_handle = false;
  size_t events_received = 0;

  // Attempt to read as many messages as possible before we exit
  for (events_received = 0; events_received < read_buffer_.size();
       events_received++) {
    errno = 0;
    int poll_status = ::poll(fds, 1, 4);
    if (poll_status == 0) {
      break;
    }

    if (poll_status < 0) {
      VLOG(1) << "Audit: poll() failed with error " << errno;
      reset_handle = true;
      break;
    }

    if ((fds[0].revents & POLLIN) == 0) {
      break;
    }

    audit_reply reply = {};
    ssize_t len = recvfrom(audit_netlink_handle_,
                           &reply.msg,
                           sizeof(reply.msg),
                           0,
                           reinterpret_cast<struct sockaddr*>(&nladdr),
                           &nladdrlen);

    if (len < 0) {
      VLOG(1) << "Audit: Failed to receive data from the audit netlink";
      reset_handle = true;
      break;
    }

    if (nladdrlen != sizeof(nladdr)) {
      VLOG(1) << "Audit: Protocol error";
      reset_handle = true;
      break;
    }

    if (nladdr.nl_pid) {
      VLOG(1) << "Audit: Invalid netlink endpoint";
      reset_handle = true;
      break;
    }

    if (!NLMSG_OK(&reply.msg.nlh, static_cast<unsigned int>(len))) {
      if (len == sizeof(reply.msg)) {
        VLOG(1) << "Audit: Netlink event too big (EFBIG)";
      } else {
        VLOG(1) << "Audit: Broken netlink event (EBADE)";
      }

      reset_handle = true;
      break;
    }

    read_buffer_[events_received] = reply;
  }

  if (events_received != 0) {
    std::unique_lock<std::mutex> lock(raw_audit_record_list_mutex_);

    raw_audit_record_list_.reserve(raw_audit_record_list_.size() +
                                   events_received);
    raw_audit_record_list_.insert(
        raw_audit_record_list_.end(),
        read_buffer_.begin(),
        std::next(read_buffer_.begin(), events_received));

    proc_thread_cv_.notify_one();
  }

  if (reset_handle) {
    VLOG(1) << "Requesting audit handle reset";
    return false;
  }

  return true;
}

bool AuditdNetlink::configureAuditService() noexcept {
  VLOG(1) << "Attempting to configure the audit service...";

  // Want to set a min sane buffer and maximum number of events/second min.
  // This is normally controlled through the audit config, but we must
  // enforce sane minimums: -b 8192 -e 100
  audit_set_backlog_wait_time(audit_netlink_handle_, 1);
  audit_set_backlog_limit(audit_netlink_handle_, 4096);
  audit_set_failure(audit_netlink_handle_, AUDIT_FAIL_SILENT);

  // Request only the highest priority of audit status messages.
  set_aumessage_mode(MSG_QUIET, DBG_NO);

  //
  // Audit rules
  //

  // Rules required by the socket_events table
  if (FLAGS_audit_allow_sockets) {
    VLOG(1) << "Enabling audit rules for the socket_events table";

    for (int syscall : SocketEventSubscriber::GetSyscallSet()) {
      monitored_syscall_list_.insert(syscall);
    }
  }

  // Rules required by the process_events table
  if (FLAGS_audit_allow_process_events) {
    VLOG(1) << "Enabling audit rules for the process_events table";

    for (int syscall : AuditProcessEventSubscriber::GetSyscallSet()) {
      monitored_syscall_list_.insert(syscall);
    }
  }

  // Rules required by the auditd_fim_events table
  if (FLAGS_audit_allow_fim_events) {
    VLOG(1) << "Enabling audit rules for the auditd_fim_events table";

    for (int syscall : AuditdFimEventSubscriber::GetSyscallSet()) {
      monitored_syscall_list_.insert(syscall);
    }
  }

  // Attempt to add each one of the rules we collected
  for (int syscall_number : monitored_syscall_list_) {
    audit_rule_data rule = {};
    audit_rule_syscall_data(&rule, syscall_number);

    // clang-format off
    int rule_add_error = audit_add_rule_data(audit_netlink_handle_, &rule,
      // We want to be notified when we exit from the syscall
      AUDIT_FILTER_EXIT,

      // Always audit this syscall event
      AUDIT_ALWAYS
    );
    // clang-format on

    // When exiting, don't remove the rules that were already installed, unless
    // we have been asked to
    if (rule_add_error >= 0) {
      if (FLAGS_audit_debug) {
        std::cout << "Audit rule installed for syscall " << syscall_number
                  << std::endl;
      }

      installed_rule_list_.push_back(rule);
      continue;
    }

    if (FLAGS_audit_debug) {
      std::cout << "Audit rule for syscall " << syscall_number
                << " could not be installed. Errno: " << (-errno) << std::endl;
    }

    if (FLAGS_audit_force_unconfigure) {
      installed_rule_list_.push_back(rule);
    }

    rule_add_error = -rule_add_error;

    if (rule_add_error != EEXIST) {
      VLOG(1) << "The following syscall number could not be added to the audit "
                 "service rules: "
              << syscall_number << ". Some of the auditd "
              << "table may not work properly (process_events, "
              << "socket_events, auditd_fim_events)";
    }
  }

  return true;
}

bool AuditdNetlink::clearAuditConfiguration() noexcept {
  int seq = audit_request_rules_list_data(audit_netlink_handle_);
  if (seq <= 0) {
    VLOG(1) << "Failed to list the audit rules";
    return false;
  }

  // Attempt to list all rules
  std::vector<AuditRuleDataObject> rule_object_list;
  auto timeout = getUnixTime() + 5;

  for (size_t read_retry = 0U; read_retry < 3U; ++read_retry) {
    if (timeout < getUnixTime()) {
      VLOG(1) << "Failed to unconfigure the audit service (timeout)";
      return false;
    }

    bool netlink_ready = false;

    for (size_t poll_retry = 0U; poll_retry < 3U; ++poll_retry) {
      pollfd fds[] = {{audit_netlink_handle_, POLLIN, 0}};

      errno = 0;
      int poll_status = ::poll(fds, 1, 4);
      if (poll_status == 0) {
        continue;
      }

      if (poll_status < 0) {
        VLOG(1) << "poll() failed with errno " << errno;
        return false;
      }

      if ((fds[0].revents & POLLIN) != 0) {
        netlink_ready = true;
        break;
      }
    }

    if (!netlink_ready) {
      VLOG(1) << "Could not read from the audit netlink";
      return false;
    }

    // Get the reply from the audit link
    struct audit_reply reply = {};
    if (audit_get_reply(
            audit_netlink_handle_, &reply, GET_REPLY_NONBLOCKING, 0) <= 0) {
      continue;
    }

    read_retry = 0;
    if (reply.nlh->nlmsg_seq != static_cast<unsigned int>(seq)) {
      continue;
    }

    if (reply.type == NLMSG_DONE) {
      // We have finished listing the rules
      break;
    }

    if (reply.type == NLMSG_ERROR && reply.error->error != 0) {
      return false;
    }

    if (reply.type != AUDIT_LIST_RULES) {
      // Skip this reply if it is not part of the rule list output
      continue;
    }

    // Save the rule
    auto reply_size = sizeof(reply) + reply.ruledata->buflen;

    AuditRuleDataObject reply_object;
    reply_object.resize(reply_size);
    if (reply_object.size() != reply_size) {
      VLOG(1) << "Failed to read the audit rule data";
      return false;
    }

    std::memcpy(reply_object.data(), reply.ruledata, reply_size);
    rule_object_list.push_back(reply_object);
  }

  // Delete each rule
  size_t error_count = 0U;
  for (auto& rule_object : rule_object_list) {
    if (!deleteAuditRule(rule_object)) {
      error_count++;
    }
  }

  if (error_count != 0U) {
    VLOG(1) << error_count << " audit rules could not be correctly removed";
    return false;
  }

  VLOG(1) << "The audit configuration has been cleared";
  return true;
}

bool AuditdNetlink::deleteAuditRule(const AuditRuleDataObject& rule_object) {
  if (NLMSG_SPACE(rule_object.size()) > MAX_AUDIT_MESSAGE_LENGTH) {
    return false;
  }

  auto rule_data =
      reinterpret_cast<const struct audit_rule_data*>(rule_object.data());

  struct audit_message request = {};
  request.nlh.nlmsg_len = static_cast<__u32>(NLMSG_SPACE(rule_object.size()));
  request.nlh.nlmsg_type = AUDIT_DEL_RULE;
  request.nlh.nlmsg_flags = NLM_F_REQUEST;
  std::memcpy(NLMSG_DATA(&request.nlh), rule_data, rule_object.size());

  struct sockaddr_nl address = {};
  address.nl_family = AF_NETLINK;

  bool success = false;

  for (size_t i = 0; i < 3; i++) {
    ssize_t bytes_sent;

    while (true) {
      errno = 0;
      bytes_sent = sendto(audit_netlink_handle_,
                          &request,
                          request.nlh.nlmsg_len,
                          0,
                          reinterpret_cast<struct sockaddr*>(&address),
                          sizeof(address));
      if (bytes_sent >= 0) {
        break;
      }

      if (errno != EINTR) {
        return false;
      }
    }

    if (bytes_sent == static_cast<ssize_t>(request.nlh.nlmsg_len)) {
      success = true;
      break;
    }
  }

  return success;
}

void AuditdNetlink::restoreAuditServiceConfiguration() noexcept {
  if (FLAGS_audit_debug) {
    std::cout << "Uninstalling audit rules..." << std::endl;
  }

  // Remove the rules we have added
  VLOG(1) << "Uninstalling the audit rules we have installed";

  for (auto& rule : installed_rule_list_) {
    audit_delete_rule_data(
        audit_netlink_handle_, &rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
  }

  installed_rule_list_.clear();

  // Restore audit configuration defaults.
  if (FLAGS_audit_debug) {
    std::cout
        << "Audit: restoring default settings and disabling the service..."
        << std::endl;
  }

  VLOG(1) << "Restoring the default configuration for the audit service";

  audit_set_backlog_limit(audit_netlink_handle_, 0);
  audit_set_backlog_wait_time(audit_netlink_handle_, 60000);
  audit_set_failure(audit_netlink_handle_, AUDIT_FAIL_PRINTK);
  audit_set_enabled(audit_netlink_handle_, AUDIT_DISABLED);
}

NetlinkStatus AuditdNetlink::acquireHandle() noexcept {
  // Returns the audit netlink status
  auto L_GetNetlinkStatus = [](int netlink_handle) -> NetlinkStatus {
    if (netlink_handle <= 0) {
      return NetlinkStatus::Error;
    }

    errno = 0;
    if (audit_request_status(netlink_handle) < 0 && errno != ENOBUFS) {
      VLOG(1) << "Failed to query the audit netlink status";
      return NetlinkStatus::Error;
    }

    auto enabled = audit_is_enabled(netlink_handle);

    if (enabled == AUDIT_IMMUTABLE || getuid() != 0 ||
        !FLAGS_audit_allow_config) {
      return NetlinkStatus::ActiveImmutable;

    } else if (enabled == AUDIT_ENABLED) {
      return NetlinkStatus::ActiveMutable;

    } else if (enabled == AUDIT_DISABLED) {
      return NetlinkStatus::Disabled;

    } else {
      return NetlinkStatus::Error;
    }
  };

  if (audit_netlink_handle_ != -1) {
    audit_close(audit_netlink_handle_);
    audit_netlink_handle_ = -1;
  }

  audit_netlink_handle_ = audit_open();
  if (audit_netlink_handle_ <= 0) {
    VLOG(1) << "Audit: failed to acquire the netlink handle";

    audit_netlink_handle_ = -1;
    return NetlinkStatus::Error;
  }

  if (audit_set_pid(audit_netlink_handle_, getpid(), WAIT_NO) < 0) {
    VLOG(1) << "Audit: failed to set the netlink owner";

    audit_close(audit_netlink_handle_);
    audit_netlink_handle_ = -1;

    return NetlinkStatus::Error;
  }

  NetlinkStatus netlink_status = L_GetNetlinkStatus(audit_netlink_handle_);
  if (FLAGS_audit_allow_config &&
      (netlink_status != NetlinkStatus::ActiveMutable &&
       netlink_status != NetlinkStatus::ActiveImmutable)) {
    if (audit_set_enabled(audit_netlink_handle_, AUDIT_ENABLED) < 0) {
      VLOG(1) << "Failed to enable the audit service";

      audit_close(audit_netlink_handle_);
      audit_netlink_handle_ = -1;

      return NetlinkStatus::Error;
    }

    if (FLAGS_audit_debug) {
      std::cout << "Audit service enabled" << std::endl;
    }
  }

  if (FLAGS_audit_allow_config) {
    if (FLAGS_audit_force_reconfigure) {
      if (!clearAuditConfiguration()) {
        audit_netlink_handle_ = -1;
        return NetlinkStatus::Error;
      }
    }

    if (!configureAuditService()) {
      return NetlinkStatus::ActiveImmutable;
    }

    if (FLAGS_audit_debug) {
      std::cout << "Audit service configured" << std::endl;
    }
  }

  return NetlinkStatus::ActiveMutable;
}
}