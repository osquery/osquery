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

/*
To closesly replicate `route print` use this query:
osquery> SELECT
           destination as "Network Destination",
           mask as "Netmask",
           gateway as "Gateway",
           address as "Interface",
           metric as "Metric"
         FROM
           routes
         JOIN
           interface_addresses
         ON
           interface_addresses.interface = routes.interface_index
         WHERE
           address_family = "IPv4"
         AND (
           mask <> 64 AND mask <> 128
        );
*/

namespace osquery {
namespace tables {

std::map<DWORD, std::string> routeType = {
    {MIB_IPROUTE_TYPE_OTHER, "other"},
    {MIB_IPROUTE_TYPE_INVALID, "invalid"},
    {MIB_IPROUTE_TYPE_DIRECT, "local"},
    {MIB_IPROUTE_TYPE_INDIRECT, "remote"},
};

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
  IP_ADAPTER_INFO AdapterInfo[32]; // naive for now
  DWORD dwBufLen = sizeof(AdapterInfo);
  DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);

  if (dwStatus == ERROR_SUCCESS) {
    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
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
    for (int i = 0; i < (int)interfaces->NumEntries; ++i) {
      MIB_IPINTERFACE_ROW currentRow = interfaces->Table[i];
      returnMapping.insert(std::pair<unsigned long, MIB_IPINTERFACE_ROW>(
          currentRow.InterfaceIndex, currentRow));
    }
  }

  return returnMapping;
}

QueryData genIPv4Routes(QueryContext& context) {
  Row r;
  QueryData results;
  DWORD dwSize = 0;
  DWORD status;
  struct in_addr addr;
  char buffer[INET_ADDRSTRLEN];
  PVOID tmpIPAddr = &addr;
  std::map<unsigned long, MIB_IPINTERFACE_ROW> interfaces =
      getInterfaceRowMapping(AF_INET);
  std::map<unsigned long, PIP_ADAPTER_INFO> adapters =
      getAdapterAddressMapping();
  PMIB_IPFORWARDTABLE ipTable =
      (MIB_IPFORWARDTABLE*)malloc(sizeof(MIB_IPFORWARDTABLE));

  if (ipTable == NULL) {
    return results;
  }

  if (GetIpForwardTable(ipTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
    free(ipTable);
    ipTable = (MIB_IPFORWARDTABLE*)malloc(dwSize);
    if (ipTable == NULL) {
      return results;
    }
  }

  status = GetIpForwardTable(ipTable, &dwSize, FALSE);
  if (status == NO_ERROR) {
    for (int i = 0; i < (int)ipTable->dwNumEntries; ++i) {
      MIB_IPFORWARDROW* currentRow = &ipTable->table[i];
      MIB_IPINTERFACE_ROW actualInterface =
          interfaces.at(currentRow->dwForwardIfIndex);
      std::string ifaceIP;

      // Special values for the loopback device, denoted as index 1
      if (currentRow->dwForwardIfIndex != 1) {
        PIP_ADAPTER_INFO actualAdapter =
            adapters.at(currentRow->dwForwardIfIndex);
        ifaceIP = actualAdapter->IpAddressList.IpAddress.String;
        r["mtu"] = INTEGER(actualInterface.NlMtu);
      } else {
        ifaceIP = "127.0.0.1";
        r["mtu"] = UNSIGNED_BIGINT(0xFFFFFFFF);
      }
      r["address_family"] = SQL_TEXT("IPv4");
      addr.S_un.S_addr = currentRow->dwForwardDest;
      InetNtop(AF_INET, tmpIPAddr, buffer, sizeof(buffer));
      r["destination"] = SQL_TEXT(buffer);
      addr.S_un.S_addr = currentRow->dwForwardMask;
      InetNtop(AF_INET, tmpIPAddr, buffer, sizeof(buffer));
      r["netmask"] = SQL_TEXT(buffer);
      addr.S_un.S_addr = currentRow->dwForwardNextHop;
      InetNtop(AF_INET, tmpIPAddr, buffer, sizeof(buffer));
      r["gateway"] = SQL_TEXT(buffer);
      r["metric"] = INTEGER(currentRow->dwForwardMetric1);
      r["type"] = routeType.at(currentRow->dwForwardType);
      r["interface"] = SQL_TEXT(ifaceIP);
      r["flags"] = SQL_TEXT("");

      results.push_back(r);
    }
  }

  // Cleanup
  FreeMibTable(ipTable);
  SecureZeroMemory(tmpIPAddr, sizeof(tmpIPAddr));
  ipTable = nullptr;
  tmpIPAddr = nullptr;

  return results;
}

QueryData genIPv6Routes(QueryContext& context) {
  Row r;
  QueryData results;
  unsigned long numEntries = 0;
  PMIB_IPFORWARD_TABLE2* ipTable = nullptr;
  ipTable = (PMIB_IPFORWARD_TABLE2*)malloc(sizeof(PMIB_IPFORWARD_TABLE2));
  GetIpForwardTable2(AF_INET6, ipTable);
  numEntries = ipTable[0]->NumEntries;

  for (unsigned long i = 0; i < numEntries; ++i) {
    auto currentRow = ipTable[0]->Table[i];
    auto addrFamily = currentRow.DestinationPrefix.Prefix.si_family;
    auto prefixLength = currentRow.DestinationPrefix.PrefixLength;
    auto prefix = currentRow.DestinationPrefix.Prefix;
    char buf[INET6_ADDRSTRLEN];
    std::string sAddrFamily;
    std::vector<std::string> flagList;
    PVOID ipAddr = nullptr;
    PVOID gateway = nullptr;
    ipAddr = (struct sockaddr_in6*)&currentRow.DestinationPrefix.Prefix.Ipv6
                 .sin6_addr;
    gateway = (struct sockaddr_in6*)&currentRow.NextHop.Ipv6.sin6_addr;

    InetNtop(addrFamily, ipAddr, (PSTR)buf, sizeof(buf));
    r["destination"] = SQL_TEXT(buf);
    InetNtop(addrFamily, gateway, (PSTR)buf, sizeof(buf));
    r["gateway"] = SQL_TEXT(buf);
    r["flags"] = SQL_TEXT("");
    r["address_family"] = SQL_TEXT("IPv6");

    // TODO: This does not exist in the Windows route.
    r["mtu"] = "nyi";

    // TODO: Metric needs to be properly calculated to match
    // what is in route.exe
    r["metric"] = INTEGER(currentRow.Metric);
    // no netmask in IPv6 routing land??
    r["netmask"] = "";

    // TODO: Type of connection lookup data structure.
    r["type"] = "nyi";

    results.push_back(r);
    SecureZeroMemory(ipAddr, sizeof(ipAddr));
    SecureZeroMemory(gateway, sizeof(gateway));
    ipAddr = nullptr;
    gateway = nullptr;
    // netmask = nullptr;
  }

  FreeMibTable(ipTable);
  ipTable = nullptr;

  return results;
}

QueryData genRoutes(QueryContext& context) {
  QueryData results;
  QueryData v4Results = genIPv4Routes(context);

  for (auto const& item : v4Results) {
    results.push_back(item);
  }

  return results;
}
}
}