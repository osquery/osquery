/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include "win_sockets.h"

namespace osquery {
namespace tables {
namespace {
const std::vector<std::string> kWinTcpStates = {
    "UNKNOWN",
    "CLOSED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RCVD",
    "ESTABLISHED",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT",
    "DELETE_TCB",
};

std::string tcpStateString(const DWORD state) {
  return state < kWinTcpStates.size() ? kWinTcpStates[state] : "UNKNOWN";
}
} // namespace

WinSockets::WinSockets() {
  auto pSockTable = allocateSocketTable(IPPROTO_TCP, AF_INET);
  if (status_.ok()) {
    tcpTable_ = static_cast<MIB_TCPTABLE_OWNER_PID*>(pSockTable);
  } else {
    TLOG << "Error allocating the TCP IPv4 socket table";
    return;
  }

  pSockTable = allocateSocketTable(IPPROTO_TCP, AF_INET6);
  if (status_.ok()) {
    tcp6Table_ = static_cast<MIB_TCP6TABLE_OWNER_PID*>(pSockTable);
  } else {
    TLOG << "Error allocating the TCP IPv6 socket table";
    return;
  }

  pSockTable = allocateSocketTable(IPPROTO_UDP, AF_INET);
  if (status_.ok()) {
    udpTable_ = static_cast<MIB_UDPTABLE_OWNER_PID*>(pSockTable);
  } else {
    TLOG << "Error allocating the UDP IPv4 socket table";
    return;
  }

  pSockTable = allocateSocketTable(IPPROTO_UDP, AF_INET6);
  if (status_.ok()) {
    udp6Table_ = static_cast<MIB_UDP6TABLE_OWNER_PID*>(pSockTable);
  } else {
    TLOG << "Error allocating the UDP IPv6 socket table";
    return;
  }
}

WinSockets::~WinSockets() {
  if (tcpTable_ != nullptr) {
    free(tcpTable_);
    tcpTable_ = nullptr;
  }
  if (tcp6Table_ != nullptr) {
    free(tcp6Table_);
    tcp6Table_ = nullptr;
  }
  if (udpTable_ != nullptr) {
    free(udpTable_);
    udpTable_ = nullptr;
  }
  if (udp6Table_ != nullptr) {
    free(udp6Table_);
    udp6Table_ = nullptr;
  }
}

void WinSockets::parseSocketTable(WinSockTableType sockType,
                                  QueryData& results) {
  unsigned int numEntries;
  switch (sockType) {
  case WinSockTableType::tcp:
    numEntries = tcpTable_->dwNumEntries;
    break;
  case WinSockTableType::tcp6:
    numEntries = tcp6Table_->dwNumEntries;
    break;
  case WinSockTableType::udp:
    numEntries = udpTable_->dwNumEntries;
    break;
  case WinSockTableType::udp6:
    numEntries = udp6Table_->dwNumEntries;
    break;
  default:
    numEntries = 0;
    break;
  }

  for (size_t i = 0; i < numEntries; i++) {
    Row r;
    std::vector<char> localAddr(128, 0x0);
    std::vector<char> remoteAddr(128, 0x0);

    switch (sockType) {
    case WinSockTableType::tcp: {
      r["protocol"] = INTEGER(IPPROTO_TCP);
      auto tcpLocalAddr = tcpTable_->table[i].dwLocalAddr;
      auto retVal =
          InetNtopA(AF_INET, &tcpLocalAddr, localAddr.data(), localAddr.size());
      if (retVal == nullptr) {
        TLOG << "Error converting network local address to string: "
             << WSAGetLastError();
      }
      r["local_port"] =
          INTEGER(ntohs(static_cast<u_short>(tcpTable_->table[i].dwLocalPort)));
      auto tcpRemoteAddr = tcpTable_->table[i].dwRemoteAddr;
      retVal = InetNtopA(
          AF_INET, &tcpRemoteAddr, remoteAddr.data(), remoteAddr.size());
      if (retVal == nullptr) {
        TLOG << "Error converting network remote address to string: "
             << WSAGetLastError();
      }
      r["remote_address"] = remoteAddr.data();
      r["remote_port"] = INTEGER(
          ntohs(static_cast<u_short>(tcpTable_->table[i].dwRemotePort)));
      r["pid"] = INTEGER(tcpTable_->table[i].dwOwningPid);
      r["family"] = INTEGER(AF_INET);
      r["state"] = tcpStateString(tcpTable_->table[i].dwState);
      break;
    }

    case WinSockTableType::tcp6: {
      r["protocol"] = INTEGER(IPPROTO_TCP);
      auto tcp6LocalAddr = tcp6Table_->table[i].ucLocalAddr;
      auto retVal = InetNtopA(
          AF_INET6, tcp6LocalAddr, localAddr.data(), localAddr.size());
      if (retVal == nullptr) {
        TLOG << "Error converting network local address to string: "
             << WSAGetLastError();
      }
      r["local_port"] = INTEGER(
          ntohs(static_cast<u_short>(tcp6Table_->table[i].dwLocalPort)));
      auto tcp6RemoteAddr = tcp6Table_->table[i].ucRemoteAddr;
      retVal = InetNtopA(
          AF_INET6, tcp6RemoteAddr, remoteAddr.data(), remoteAddr.size());
      if (retVal == nullptr) {
        TLOG << "Error converting network remote address to string: "
             << WSAGetLastError();
      }
      r["remote_address"] = remoteAddr.data();
      r["remote_port"] = INTEGER(
          ntohs(static_cast<u_short>(tcp6Table_->table[i].dwRemotePort)));
      r["pid"] = INTEGER(tcp6Table_->table[i].dwOwningPid);
      r["family"] = INTEGER(AF_INET6);
      r["state"] = tcpStateString(tcp6Table_->table[i].dwState);
      break;
    }

    case WinSockTableType::udp: {
      r["protocol"] = INTEGER(IPPROTO_UDP);
      auto udpLocalAddr = udpTable_->table[i].dwLocalAddr;
      auto retVal =
          InetNtopA(AF_INET, &udpLocalAddr, localAddr.data(), localAddr.size());
      if (retVal == nullptr) {
        TLOG << "Error converting network local address to string: "
             << WSAGetLastError();
      }
      r["local_port"] =
          INTEGER(ntohs(static_cast<u_short>(udpTable_->table[i].dwLocalPort)));
      r["remote_address"] = "0";
      r["remote_port"] = INTEGER(0);
      r["pid"] = INTEGER(udpTable_->table[i].dwOwningPid);
      r["family"] = INTEGER(AF_INET);
      break;
    }

    case WinSockTableType::udp6: {
      r["protocol"] = INTEGER(IPPROTO_UDP);
      auto udp6LocalAddr = udp6Table_->table[i].ucLocalAddr;
      auto retVal = InetNtopA(
          AF_INET6, udp6LocalAddr, localAddr.data(), localAddr.size());
      if (retVal == nullptr) {
        TLOG << "Error converting network local address to string: "
             << WSAGetLastError();
      }
      r["local_port"] = INTEGER(
          ntohs(static_cast<u_short>(udp6Table_->table[i].dwLocalPort)));
      r["remote_address"] = "0";
      r["remote_port"] = INTEGER(0);
      r["pid"] = INTEGER(udp6Table_->table[i].dwOwningPid);
      r["family"] = INTEGER(AF_INET6);
      break;
    }
    default:
      break;
    }

    r["local_address"] = localAddr.data();
    results.push_back(r);
  }
}

void* WinSockets::allocateSocketTable(unsigned long protocol,
                                      unsigned long family) {
  unsigned long ret = 0;
  unsigned long buffsize = 0;
  void* pSockTable = nullptr;

  /// Allocate the TCP Socket Tables
  if (protocol == IPPROTO_TCP) {
    ret = GetExtendedTcpTable(
        pSockTable, &buffsize, true, family, TCP_TABLE_OWNER_PID_ALL, 0);
    if (ret == ERROR_INSUFFICIENT_BUFFER) {
      pSockTable = static_cast<void*>(malloc(buffsize));
      if (pSockTable == nullptr) {
        status_ = Status(
            1, "Unable to allocate sufficient memory for the TCP socket table");
      }
    }
    ret = GetExtendedTcpTable(pSockTable,
                              reinterpret_cast<PULONG>(&buffsize),
                              true,
                              family,
                              TCP_TABLE_OWNER_PID_ALL,
                              0);
    if (ret != NO_ERROR) {
      status_ = Status(1,
                       "Error retrieving the socket table: ( " +
                           std::to_string(GetLastError()) + " )");
    }
  }
  /// Allocate the UDP Socket Tables
  else {
    ret = GetExtendedUdpTable(pSockTable,
                              reinterpret_cast<PULONG>(&buffsize),
                              true,
                              family,
                              UDP_TABLE_OWNER_PID,
                              0);
    if (ret == ERROR_INSUFFICIENT_BUFFER) {
      pSockTable = static_cast<void*>(malloc(buffsize));
      if (pSockTable == nullptr) {
        status_ = Status(
            1, "Unable to allocate sufficient memory for the UDP socket table");
      }
    }
    ret = GetExtendedUdpTable(pSockTable,
                              reinterpret_cast<PULONG>(&buffsize),
                              true,
                              family,
                              UDP_TABLE_OWNER_PID,
                              0);
    if (ret != NO_ERROR) {
      status_ = Status(1,
                       "Error retrieving the socket table: ( " +
                           std::to_string(GetLastError()) + " )");
    }
  }
  return pSockTable;
}

QueryData genOpenSockets(QueryContext& context) {
  QueryData results;
  WinSockets sockTable;

  sockTable.parseSocketTable(WinSockTableType::tcp, results);

  sockTable.parseSocketTable(WinSockTableType::tcp6, results);

  sockTable.parseSocketTable(WinSockTableType::udp, results);

  sockTable.parseSocketTable(WinSockTableType::udp6, results);

  return results;
}
} // namespace tables
} // namespace osquery
