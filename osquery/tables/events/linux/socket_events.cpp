/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <asm/unistd_64.h>

#include <boost/algorithm/string.hpp>

#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/core/conversions.h"
#include "osquery/events/linux/auditeventpublisher.h"
#include "osquery/tables/events/linux/socket_events.h"

namespace osquery {

FLAG(bool,
     audit_allow_sockets,
     false,
     "Allow the audit publisher to install socket-related rules");

HIDDEN_FLAG(bool,
            audit_allow_unix,
            false,
            "Allow socket events to collect domain sockets");

HIDDEN_FLAG(
    bool,
    audit_disable_accept_syscalls,
    false,
    "Prevents socket_events from collecting accept()/accept4() syscall events");

// Depend on the external getUptime table method.
namespace tables {
extern long getUptime();
}

std::string ip4FromSaddr(const std::string& saddr, ushort offset) {
  long const result = tryTo<long>(saddr.substr(offset, 8), 16).takeOr(0l);
  return std::to_string((result & 0xff000000) >> 24) + '.' +
         std::to_string((result & 0x00ff0000) >> 16) + '.' +
         std::to_string((result & 0x0000ff00) >> 8) + '.' +
         std::to_string((result & 0x000000ff));
}

bool parseSockAddr(int syscall_number,
                   const std::string& saddr,
                   Row& row,
                   bool& unix_socket) {
  unix_socket = false;

  row["protocol"] = '0';

  row["local_address"] = "";
  row["local_port"] = "0";

  row["remote_address"] = "";
  row["remote_port"] = "0";

  // Set the action based on the syscall number
  if (syscall_number == __NR_connect) {
    row["action"] = "connect";
  } else if (syscall_number == __NR_bind) {
    row["action"] = "bind";
  } else if (syscall_number == __NR_accept || syscall_number == __NR_accept4) {
    row["action"] = "accept";
  } else {
    return false;
  }

  // Select the right column depending on the syscall we are
  // handling
  std::string port_column;
  std::string address_column;

  if (syscall_number == __NR_bind) {
    port_column = "local_port";
    address_column = "local_address";
  } else {
    port_column = "remote_port";
    address_column = "remote_address";
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

  return Status(0, "OK");
}

Status SocketEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  std::vector<Row> emitted_row_list;
  auto status = ProcessEvents(emitted_row_list, ec->audit_events);
  if (!status.ok()) {
    return status;
  }

  addBatch(emitted_row_list);
  return Status(0, "Ok");
}

Status SocketEventSubscriber::ProcessEvents(
    std::vector<Row>& emitted_row_list,
    const std::vector<AuditEvent>& event_list) noexcept {
  emitted_row_list.clear();

  emitted_row_list.reserve(event_list.size());

  for (const auto& event : event_list) {
    if (event.type != AuditEvent::Type::Syscall) {
      continue;
    }

    Row row = {};
    const auto& event_data = boost::get<SyscallAuditEventData>(event.data);
    if (GetSyscallSet().count(event_data.syscall_number) == 0) {
      continue;
    }

    /*
     * This is how syscalls are reported now:
     *
     * - connect, bind
     * Report always. If the event succeeded, then the socket is blocking and
     * we know for sure that the operation has happened.
     *
     * If the event is marked as failed, we can end up in the following cases:
     * 1. Blocking socket: the syscall has definitely failed.
     * 2. Non-blocking socket: the syscall has returned -1 with errno
     * EINPROGRESS. We can't determine if the operation will fail or not
     * (without tracking all socket operations).
     *
     * - accept
     * Report only when succeeded; the non-blocking socket attribute has no
     * effect on this syscall.
     *
     */

    bool skip_event = true;

    switch (event_data.syscall_number) {
    case __NR_connect:
    case __NR_bind: {
      skip_event = false;
      if (event_data.succeeded) {
        row["status"] = "succeeded";
      } else {
        row["status"] = "unknown";
      }
      break;
    }

    case __NR_accept:
    case __NR_accept4: {
      if (event_data.succeeded) {
        skip_event = false;
        row["status"] = "succeeded";
      }

      break;
    }
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
    row["success"] =
        (syscall_event_record->fields.at("success") == "yes") ? "1" : "0";
    row["uptime"] = std::to_string(tables::getUptime());

    // Set some sane defaults and then attempt to parse the sockaddr value
    bool unix_socket;
    if (!parseSockAddr(event_data.syscall_number, saddr, row, unix_socket)) {
      VLOG(1) << "Malformed syscall event. The saddr field in the "
                 "AUDIT_SOCKADDR record could not be parsed: \""
              << saddr << "\"";
      continue;
    }

    if (unix_socket && !FLAGS_audit_allow_unix) {
      continue;
    }

    emitted_row_list.push_back(row);
  }

  return Status(0, "Ok");
}

const std::unordered_set<int>& SocketEventSubscriber::GetSyscallSet() noexcept {
  static const std::unordered_set<int> reduced_syscall_set = {__NR_bind,
                                                              __NR_connect};

  static const std::unordered_set<int> full_syscall_set = {
      __NR_bind, __NR_connect, __NR_accept, __NR_accept4};

  if (FLAGS_audit_disable_accept_syscalls) {
    return reduced_syscall_set;
  } else {
    return full_syscall_set;
  }
}
} // namespace osquery
