/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#define WIN32_LEAN_AND_MEAN

#include <string>
#include <windows.h>
#include <winsock2.h>

#include <wS2tcpip.h>
#include <ws2ipdef.h>

#include <iphlpapi.h>
#include <mstcpip.h>

#include <boost/algorithm/string/join.hpp>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

PMIB_IPINTERFACE_TABLE getInterfaces(int type = AF_UNSPEC) {
  PMIB_IPINTERFACE_TABLE interfaceTable = nullptr;

  auto dwRetVal = GetIpInterfaceTable(type, &interfaceTable);
  if (dwRetVal != NO_ERROR) {
    return nullptr;
  }

  return interfaceTable;
}

std::map<unsigned long, PIP_ADAPTER_INFO> getAdapterAddressMapping() {
  std::map<unsigned long, PIP_ADAPTER_INFO> returnMapping;
  DWORD dwBufLen = 0;
  auto dwStatus = GetAdaptersInfo(NULL, &dwBufLen);

  if (dwStatus == ERROR_BUFFER_OVERFLOW) {
    auto pAdapterInfo = static_cast<PIP_ADAPTER_INFO>(malloc(dwBufLen));
    dwStatus = GetAdaptersInfo(pAdapterInfo, &dwBufLen);

    if (dwStatus != S_OK) {
      return returnMapping;
    }

    while (pAdapterInfo) {
      returnMapping.insert(std::pair<unsigned long, PIP_ADAPTER_INFO>(
          pAdapterInfo->Index, pAdapterInfo));
      pAdapterInfo = pAdapterInfo->Next;
    }
  }

  return returnMapping;
}

std::map<unsigned long, MIB_IPINTERFACE_ROW> getInterfaceRowMapping(
    int type = AF_UNSPEC) {
  std::map<unsigned long, MIB_IPINTERFACE_ROW> returnMapping;
  PMIB_IPINTERFACE_TABLE interfaces;

  if ((interfaces = getInterfaces(type)) != nullptr) {
    for (unsigned long i = 0; i < interfaces->NumEntries; ++i) {
      MIB_IPINTERFACE_ROW currentRow = interfaces->Table[i];
      returnMapping.insert(std::pair<unsigned long, MIB_IPINTERFACE_ROW>(
          currentRow.InterfaceIndex, currentRow));
    }
  }

  return returnMapping;
}

QueryData genIPRoutes(QueryContext& context) {
  QueryData results;
  PMIB_IPFORWARD_TABLE2* ipTable = nullptr;

  ipTable = static_cast<PMIB_IPFORWARD_TABLE2*>(
      malloc(sizeof(PMIB_IPFORWARD_TABLE2)));
  auto result = GetIpForwardTable2(AF_UNSPEC, ipTable);

  if (result != S_OK) {
    FreeMibTable(ipTable);

    return results;
  }

  auto numEntries = ipTable[0]->NumEntries;
  auto interfaces = getInterfaceRowMapping();
  auto adapters = getAdapterAddressMapping();

  for (unsigned long i = 0; i < numEntries; ++i) {
    Row r;
    std::string interfaceIpAddress;
    PVOID ipAddress = nullptr;
    PVOID gateway = nullptr;
    auto currentRow = ipTable[0]->Table[i];
    auto addrFamily = currentRow.DestinationPrefix.Prefix.si_family;
    auto actualInterface = interfaces.at(currentRow.InterfaceIndex);
    if (addrFamily == AF_INET6) {
      r["mtu"] = INTEGER(actualInterface.NlMtu);
      // These are all technically "on-link" addresses according to
      // `route print -6`.
      r["type"] = "local";
      ipAddress = reinterpret_cast<struct sockaddr_in6*>(
          &currentRow.DestinationPrefix.Prefix.Ipv6.sin6_addr);
      gateway = reinterpret_cast<struct sockaddr_in6*>(
          &currentRow.NextHop.Ipv6.sin6_addr);
    } else if (addrFamily == AF_INET) {
      ipAddress = reinterpret_cast<struct sockaddr_in*>(
          &currentRow.DestinationPrefix.Prefix.Ipv4.sin_addr);
      gateway = reinterpret_cast<struct sockaddr_in*>(
          &currentRow.NextHop.Ipv4.sin_addr);

      // The software loopback is not returned by GetAdaptersInfo, so any
      // lookups into that index must be skipped and default values set.
      PIP_ADAPTER_INFO actualAdapter = nullptr;
      if (currentRow.InterfaceIndex != 1) {
        actualAdapter = adapters.at(currentRow.InterfaceIndex);
        interfaceIpAddress = actualAdapter->IpAddressList.IpAddress.String;
        r["mtu"] = INTEGER(actualInterface.NlMtu);
      } else {
        interfaceIpAddress = "127.0.0.1";
        r["mtu"] = UNSIGNED_BIGINT(0xFFFFFFFF);
      }
      r["type"] = currentRow.Loopback ? "local" : "remote";
    }
    std::vector<char> buffer(INET6_ADDRSTRLEN);
    InetNtop(addrFamily, ipAddress, buffer.data(), buffer.size());
    r["destination"] = SQL_TEXT(buffer.data());
    InetNtop(addrFamily, gateway, buffer.data(), buffer.size());
    r["gateway"] = SQL_TEXT(buffer.data());
    r["interface"] = SQL_TEXT(interfaceIpAddress);
    r["metric"] = INTEGER(currentRow.Metric + actualInterface.Metric);
    r["netmask"] =
        SQL_TEXT(std::to_string(currentRow.DestinationPrefix.PrefixLength));
    // TODO: implement routes flags
    r["flags"] = SQL_TEXT("-1");

    results.push_back(r);

    // Cleanup
    SecureZeroMemory(ipAddress, sizeof(ipAddress));
    SecureZeroMemory(gateway, sizeof(gateway));
    buffer.clear();

    ipAddress = nullptr;
    gateway = nullptr;
  }

  FreeMibTable(ipTable);
  interfaces.clear();
  adapters.clear();

  return results;
}

QueryData genRoutes(QueryContext& context) {
  QueryData results;
  QueryData routes = genIPRoutes(context);

  for (auto const& item : routes) {
    results.push_back(item);
  }
  return results;
}
}
}