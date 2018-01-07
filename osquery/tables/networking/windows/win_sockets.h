/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <ws2tcpip.h>

#include <Iphlpapi.h>
#include <windows.h>
#include <winsock2.h>

#include <boost/noncopyable.hpp>

namespace osquery {
namespace tables {

enum class WinSockTableType { tcp, tcp6, udp, udp6 };

class WinSockets : private boost::noncopyable {
 public:
  /// Retrieves all of the socket table structures from the Windows API
  WinSockets();

  /// Ensures that all Socket tables have been deallocated
  ~WinSockets();

  /// Parses all of the socket entries and populates the results QueryData
  void parseSocketTable(WinSockTableType sockType, QueryData& results);

  /// Returns the status of the Sockets Table
  Status getStatus() const {
    return status_;
  };

 private:
  Status status_;
  MIB_TCPTABLE_OWNER_PID* tcpTable_ = nullptr;
  MIB_TCP6TABLE_OWNER_PID* tcp6Table_ = nullptr;
  MIB_UDPTABLE_OWNER_PID* udpTable_ = nullptr;
  MIB_UDP6TABLE_OWNER_PID* udp6Table_ = nullptr;

  /// Helper function to allocate a table based off of family and protocol
  void* allocateSocketTable(unsigned long protocol, unsigned long family);
};
}
}
