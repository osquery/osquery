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

QueryData genRoutes(QueryContext& context) {
  QueryData results;
  Row r;
  unsigned long numEntries = 0;
  PMIB_IPFORWARD_TABLE2* ipTable = nullptr;
  ipTable = (PMIB_IPFORWARD_TABLE2*)malloc(sizeof(PMIB_IPFORWARD_TABLE2));
  GetIpForwardTable2(AF_UNSPEC, ipTable);
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

    if (addrFamily == AF_INET) {
      ipAddr = (struct sockaddr_in*)&currentRow.DestinationPrefix.Prefix.Ipv4
                   .sin_addr;
      gateway = (struct sockaddr_in*)&currentRow.NextHop.Ipv4.sin_addr;
      sAddrFamily = "IPv4";
    } else {
      ipAddr = (struct sockaddr_in6*)&currentRow.DestinationPrefix.Prefix.Ipv6
                   .sin6_addr;
      gateway = (struct sockaddr_in6*)&currentRow.NextHop.Ipv6.sin6_addr;
      sAddrFamily = "IPv6";
    }

    r["interface_index"] = INTEGER(currentRow.InterfaceIndex);
    InetNtop(addrFamily, ipAddr, (PSTR)buf, sizeof(buf));
    r["destination"] = SQL_TEXT(buf);

    // nexthop is equivalent to gateway in POSIX
    InetNtop(addrFamily, gateway, (PSTR)buf, sizeof(buf));
    r["gateway"] = SQL_TEXT(buf);

    // Construct a string to represent the flags
    if (currentRow.Publish == (BOOLEAN) true) {
      flagList.push_back("P");
    }
    if (currentRow.AutoconfigureAddress == (BOOLEAN) true) {
      flagList.push_back("A");
    }
    if (currentRow.Immortal == (BOOLEAN) true) {
      flagList.push_back("I");
    }
    if (currentRow.Loopback == (BOOLEAN) true) {
      flagList.push_back("L");
    }
    r["flags"] = SQL_TEXT(boost::algorithm::join(flagList, ""));

    r["address_family"] = SQL_TEXT(sAddrFamily);

    // TODO: This does not exist in the Windows route.
    r["mtu"] = "nyi";

    // TODO: Metric needs to be properly calculated to match
    // what is in route.exe
    r["metric"] = INTEGER(currentRow.Metric);

    // TODO: The netmask needs to be calculated... somehow???
    r["netmask"] = "nyi";

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
}
}