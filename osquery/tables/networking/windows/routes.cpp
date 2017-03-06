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

#include <boost/algorithm/string/join.hpp>
#include <osquery/tables.h>
#include <string>
#include <windows.h>
#include <winsock2.h>

#include <wS2tcpip.h>
#include <ws2ipdef.h>

#include <iphlpapi.h>
#include <mstcpip.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace osquery {
namespace tables {

PMIB_IPINTERFACE_TABLE getInterfaces(int type = AF_UNSPEC) {
  DWORD dwRetVal = 0;
  PMIB_IPINTERFACE_TABLE interfaceTable = nullptr;

  dwRetVal = GetIpInterfaceTable(type, &interfaceTable);
  if (dwRetVal != NO_ERROR) {
    return nullptr;
  }

  return interfaceTable;
}

std::map<unsigned long, PIP_ADAPTER_INFO> getAdapterAddressMapping() {
  std::map<unsigned long, PIP_ADAPTER_INFO> returnMapping;
  DWORD dwBufLen = 0;
  DWORD dwStatus = GetAdaptersInfo(NULL, &dwBufLen);

  if (dwStatus == ERROR_BUFFER_OVERFLOW) {
    PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)malloc(dwBufLen);
    dwStatus = GetAdaptersInfo(pAdapterInfo, &dwBufLen);
    if (dwStatus == S_OK) {
      while (pAdapterInfo) {
        returnMapping.insert(std::pair<unsigned long, PIP_ADAPTER_INFO>(
            pAdapterInfo->Index, pAdapterInfo));
        pAdapterInfo = pAdapterInfo->Next;
      }
    }
  }

  return returnMapping;
}

std::map<unsigned long, MIB_IPINTERFACE_ROW> getInterfaceRowMapping(
    int type = AF_UNSPEC) {
  std::map<unsigned long, MIB_IPINTERFACE_ROW> returnMapping;
  PMIB_IPINTERFACE_TABLE interfaces;

  if ((interfaces = getInterfaces(type)) != nullptr) {
    for (int i = 0; i < (int)interfaces->NumEntries; ++i) {
      MIB_IPINTERFACE_ROW currentRow = interfaces->Table[i];
      returnMapping.insert(std::pair<unsigned long, MIB_IPINTERFACE_ROW>(
          currentRow.InterfaceIndex, currentRow));
    }
  }

  return returnMapping;
}

QueryData genIPRoutes(QueryContext& context) {
  Row r;
  QueryData results;
  unsigned long numEntries = 0;
  auto interfaces = getInterfaceRowMapping();
  auto adapters = getAdapterAddressMapping();
  PMIB_IPFORWARD_TABLE2* ipTable = nullptr;
  ipTable = (PMIB_IPFORWARD_TABLE2*)(malloc(sizeof(PMIB_IPFORWARD_TABLE2)));
  GetIpForwardTable2(AF_UNSPEC, ipTable);
  numEntries = ipTable[0]->NumEntries;

  for (unsigned long i = 0; i < numEntries; ++i) {
    PIP_ADAPTER_INFO actualAdapter = nullptr;
    auto currentRow = ipTable[0]->Table[i];
    std::string ifaceIP;
    auto addrFamily = currentRow.DestinationPrefix.Prefix.si_family;
    auto actualInterface = interfaces.at(currentRow.InterfaceIndex);
    char buf[INET6_ADDRSTRLEN];
    PVOID ipAddr = nullptr;
    PVOID gateway = nullptr;
    if (addrFamily == AF_INET6) {
      r["mtu"] = INTEGER(actualInterface.NlMtu);
      // These are all technically "on-link" addresses according to
      // `route print -6`.
      r["type"] = "local";
      ipAddr = (struct sockaddr_in6*)(&currentRow.DestinationPrefix.Prefix.Ipv6
                                           .sin6_addr);
      gateway = (struct sockaddr_in6*)(&currentRow.NextHop.Ipv6.sin6_addr);
    } else if (addrFamily == AF_INET) {
      ipAddr = (struct sockaddr_in*)(&currentRow.DestinationPrefix.Prefix.Ipv4
                                          .sin_addr);
      gateway = (struct sockaddr_in*)(&currentRow.NextHop.Ipv4.sin_addr);

      // The software loopback is not returned by GetAdaptersInfo, so any
      // lookups into that index must be skipped and default values set.
      if (currentRow.InterfaceIndex != 1) {
        actualAdapter = adapters.at(currentRow.InterfaceIndex);
        ifaceIP = actualAdapter->IpAddressList.IpAddress.String;
        r["mtu"] = INTEGER(actualInterface.NlMtu);
      } else {
        ifaceIP = "127.0.0.1";
        r["mtu"] = UNSIGNED_BIGINT(0xFFFFFFFF);
      }
      if (currentRow.Loopback == TRUE) {
        r["type"] = "local";
      } else {
        r["type"] = "remote";
      }
    }
    InetNtop(addrFamily, ipAddr, (PSTR)buf, sizeof(buf));
    r["destination"] = SQL_TEXT(buf);
    InetNtop(addrFamily, gateway, (PSTR)buf, sizeof(buf));
    r["gateway"] = SQL_TEXT(buf);
    r["interface"] = SQL_TEXT(ifaceIP);
    r["metric"] = INTEGER(currentRow.Metric + actualInterface.Metric);
    r["netmask"] =
        SQL_TEXT(std::to_string(currentRow.DestinationPrefix.PrefixLength));
    // WTF goes here?? I don't think Windows has a concept of flags for its
    // routes :(
    r["flags"] = SQL_TEXT("");

    results.push_back(r);

    // Cleanup
    SecureZeroMemory(ipAddr, sizeof(ipAddr));
    SecureZeroMemory(gateway, sizeof(gateway));
    ipAddr = nullptr;
    gateway = nullptr;
  }

  FreeMibTable(ipTable);
  ipTable = nullptr;

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