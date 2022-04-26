/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <asm/unistd.h>
#include <boost/algorithm/string.hpp>

#include <osquery/core/flags.h>
#include <osquery/events/linux/auditeventpublisher.h>
#include <osquery/events/linux/socket_events.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/events/linux/socket_events.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {

DECLARE_bool(audit_allow_sockets);
DECLARE_bool(audit_allow_accept_socket_events);

HIDDEN_FLAG(bool,
            audit_allow_unix,
            false,
            "Allow socket events to collect domain sockets");

FLAG(bool,
     audit_allow_failed_socket_events,
     false,
     "Include rows for socket events that have failed");

FLAG(bool,
     audit_allow_null_accept_socket_events,
     false,
     "Allow non-blocking accept() syscalls that returned EAGAIN/EWOULDBLOCK");

std::string ip4FromSaddr(const std::string& saddr, ushort offset) {
  long const result = tryTo<long>(saddr.substr(offset, 8), 16).takeOr(0l);
  return std::to_string((result & 0xff000000) >> 24) + '.' +
         std::to_string((result & 0x00ff0000) >> 16) + '.' +
         std::to_string((result & 0x0000ff00) >> 8) + '.' +
         std::to_string((result & 0x000000ff));
}

bool SocketEventSubscriber::parseSockAddr(const std::string& saddr,
                                          Row& row,
                                          bool& unix_socket) {
  unix_socket = false;

  std::string address_column;
  std::string port_column;
  if (row["action"] == "bind") {
    address_column = "local_address";
    port_column = "local_port";

    row["remote_address"] = "0";
    row["remote_port"] = "0";
  } else {
    address_column = "remote_address";
    port_column = "remote_port";

    row["local_address"] = "0";
    row["local_port"] = "0";
  }

  // The protocol is not included in the audit message.
  if (saddr[0] == '0' && saddr[1] == '2') {
    // IPv4
    row["family"] = '2';
    long const result = tryTo<long>(saddr.substr(4, 4), 16).takeOr(0l);
    row[port_column] = INTEGER(result);
    row[address_column] = ip4FromSaddr(saddr, 8);
  } else if (saddr[0] == '0' && saddr[1] == 'A') {
    // IPv6
    row["family"] = "10";
    long const result = tryTo<long>(saddr.substr(4, 4), 16).takeOr(0l);
    row[port_column] = INTEGER(result);
    std::string address;
    for (size_t i = 0; i < 8; ++i) {
      address += saddr.substr(16 + (i * 4), 4);
      if (i == 0 || i % 7 != 0) {
        address += ':';
      }
    }
    boost::algorithm::to_lower(address);
    row[address_column] = std::move(address);
  } else if (saddr[0] == '0' && saddr[1] == '1' && saddr.size() > 6) {
    unix_socket = true;

    row["family"] = '1';
    off_t begin = (saddr[4] == '0' && saddr[5] == '0') ? 6 : 4;
    auto end = saddr.substr(begin).find("00");
    end = (end == std::string::npos) ? saddr.size() : end + 4;
    try {
      row["socket"] = boost::algorithm::unhex(saddr.substr(begin, end - begin));
    } catch (const boost::algorithm::hex_decode_error& e) {
      row["socket"] = "unknown";
    }
  } else {
    // No idea!
    return false;
  }
  return true;
}

REGISTER(SocketEventSubscriber, "event_subscriber", "socket_events");

Status SocketEventSubscriber::init() {
  if (!FLAGS_audit_allow_sockets) {
    return Status(1, "Subscriber disabled via configuration");
  }

  auto sc = createSubscriptionContext();
  subscribe(&SocketEventSubscriber::Callback, sc);

  return Status::success();
}

Status SocketEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  std::vector<Row> emitted_row_list;
  auto status = ProcessEvents(emitted_row_list,
                              ec->audit_events,
                              FLAGS_audit_allow_failed_socket_events,
                              FLAGS_audit_allow_unix,
                              FLAGS_audit_allow_accept_socket_events,
                              FLAGS_audit_allow_null_accept_socket_events);
  if (!status.ok()) {
    return status;
  }

  addBatch(emitted_row_list);
  return Status::success();
}

Status SocketEventSubscriber::ProcessEvents(
    std::vector<Row>& emitted_row_list,
    const std::vector<AuditEvent>& event_list,
    bool allow_failed_socket_events,
    bool allow_unix_socket_events,
    bool allow_accept_events,
    bool allow_null_accept_events) noexcept {
  emitted_row_list.clear();
  emitted_row_list.reserve(event_list.size());

  for (const auto& event : event_list) {
    if (event.type != AuditEvent::Type::Syscall) {
      continue;
    }

    Row row = {};
    const auto& event_data = boost::get<SyscallAuditEventData>(event.data);

    bool skip_event{false};
    switch (event_data.syscall_number) {
    case __NR_bind:
      row["action"] = "bind";
      break;

    case __NR_connect:
      row["action"] = "connect";
      break;

    case __NR_accept:
    case __NR_accept4:
      row["action"] = "accept";
      skip_event = !allow_accept_events;
      break;

    default:
      skip_event = true;
      break;
    }

    if (skip_event) {
      continue;
    }

    const AuditEventRecord* syscall_event_record =
        GetEventRecord(event, AUDIT_SYSCALL);
    if (syscall_event_record == nullptr) {
      VLOG(1) << "Malformed syscall event. The AUDIT_SYSCALL record "
                 "is missing";
      continue;
    }

    /*
     * Even though an event may have been marked as failed, the connect
     * event can still be changed to "in_progress" if they are operating on
     * non-blocking sockets and the return value was EINPROGRESS.
     *
     * accept/accept4 syscalls that reported failure with EAGAIN/EWOULDBLOCK
     * are changed to "no_client" if the required configuration flag is
     * present.
     */

    enum class SyscallStatus {
      Failed,
      Succeeded,
      InProgress,
      NoClient,
    } event_status{event_data.succeeded ? SyscallStatus::Succeeded
                                        : SyscallStatus::Failed};

    if (!event_data.succeeded && (event_data.syscall_number == __NR_connect ||
                                  event_data.syscall_number == __NR_accept ||
                                  event_data.syscall_number == __NR_accept4)) {
      int exit_code{};

      {
        std::uint64_t value{};
        if (!GetIntegerFieldFromMap(
                value, syscall_event_record->fields, "exit")) {
          VLOG(1) << "Malformed syscall event. The 'exit' field in the "
                     "AUDIT_SYSCALL record is missing";

          continue;
        }

        exit_code = static_cast<int>(value);
      }

      switch (event_data.syscall_number) {
      case __NR_connect:
        if (exit_code == -EINPROGRESS) {
          event_status = SyscallStatus::InProgress;
        }

        break;

      case __NR_accept:
      case __NR_accept4:
        if (exit_code == -EAGAIN && allow_null_accept_events) {
          event_status = SyscallStatus::NoClient;
        }

        break;
      }
    }

    if (event_status == SyscallStatus::Failed && !allow_failed_socket_events) {
      continue;
    }

    if (event_status == SyscallStatus::NoClient && !allow_null_accept_events) {
      continue;
    }

    switch (event_status) {
    case SyscallStatus::Failed:
      row["status"] = "failed";
      row["success"] = "0";
      break;

    case SyscallStatus::Succeeded:
      row["status"] = "succeeded";
      row["success"] = "1";
      break;

    case SyscallStatus::InProgress:
      row["status"] = "in_progress";
      row["success"] = "1";
      break;

    case SyscallStatus::NoClient:
      row["status"] = "no_client";
      row["success"] = "1";
      break;
    }

    const AuditEventRecord* sockaddr_event_record =
        GetEventRecord(event, AUDIT_SOCKADDR);
    if (sockaddr_event_record == nullptr) {
      VLOG(1) << "Malformed syscall event. The AUDIT_SOCKADDR record "
                 "is missing";
      continue;
    }

    std::string saddr;
    GetStringFieldFromMap(saddr, sockaddr_event_record->fields, "saddr");
    if (saddr.size() < 4) {
      VLOG(1) << "Invalid saddr field in AUDIT_SOCKADDR: \"" << saddr << "\"";
      continue;
    }

    // skip operations on NETLINK_ROUTE sockets
    if (saddr[0] == '1' && saddr[1] == '0') {
      continue;
    }

    CopyFieldFromMap(row, syscall_event_record->fields, "auid");
    CopyFieldFromMap(row, syscall_event_record->fields, "pid");
    GetStringFieldFromMap(row["fd"], syscall_event_record->fields, "a0");

    row["path"] = DecodeAuditPathValues(syscall_event_record->fields.at("exe"));
    row["fd"] = syscall_event_record->fields.at("a0");
    row["uptime"] = std::to_string(getUptime());

    // Set some sane defaults and then attempt to parse the sockaddr value
    row["protocol"] = '0';
    row["local_port"] = '0';
    row["remote_port"] = '0';

    bool unix_socket;
    if (!parseSockAddr(saddr, row, unix_socket)) {
      VLOG(1) << "Malformed syscall event. The saddr field in the "
                 "AUDIT_SOCKADDR record could not be parsed: \""
              << saddr << "\"";
      continue;
    }

    if (unix_socket && !allow_unix_socket_events) {
      continue;
    }

    emitted_row_list.push_back(row);
  }

  return Status::success();
}
} // namespace osquery
