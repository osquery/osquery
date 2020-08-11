/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <mstcpip.h>
#include <wS2tcpip.h>
#include <winsock2.h>
// The following headers need to be included in this specific order
// clang-format off
#include <ws2def.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
// clang-format on

#include <boost/algorithm/string/join.hpp>
#include <osquery/logger/logger.h>
#include <osquery/core/tables.h>

#include <osquery/utils/conversions/tryto.h>
#include "osquery/core/windows/wmi.h"

#include <memory>
#include <string>

namespace osquery {
namespace tables {

std::map<DWORD, IP_ADAPTER_INFO> getAdapterAddressMapping() {
  std::map<DWORD, IP_ADAPTER_INFO> returnMapping;
  auto dwBufLen = 0UL;
  auto dwStatus = GetAdaptersInfo(NULL, &dwBufLen);

  if (dwStatus != ERROR_BUFFER_OVERFLOW) {
    return returnMapping;
  }

  std::vector<BYTE> buffer(dwBufLen);
  auto pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
  dwStatus = GetAdaptersInfo(pAdapterInfo, &dwBufLen);

  if (dwStatus != NO_ERROR) {
    return returnMapping;
  }

  while (pAdapterInfo != nullptr) {
    const auto& adapter = *pAdapterInfo;
    const auto& index = pAdapterInfo->Index;
    returnMapping.insert(std::make_pair(index, adapter));
    pAdapterInfo = pAdapterInfo->Next;
  }

  buffer.clear();

  return returnMapping;
}

QueryData genRoutes(QueryContext& context) {
  QueryData results;
  PMIB_IPFORWARD_TABLE2 ipTable = nullptr;
  auto result = GetIpForwardTable2(AF_UNSPEC, &ipTable);

  if (result != NO_ERROR) {
    FreeMibTable(ipTable);

    return results;
  }

  auto numEntries = ipTable[0].NumEntries;
  auto adapters = getAdapterAddressMapping();

  for (unsigned long i = 0; i < numEntries; ++i) {
    Row r;
    std::string interfaceIpAddress;
    MIB_IPINTERFACE_ROW actualInterface;
    const auto& currentRow = ipTable[0].Table[i];
    auto addrFamily = currentRow.DestinationPrefix.Prefix.si_family;

    actualInterface.Family = currentRow.DestinationPrefix.Prefix.si_family;
    actualInterface.InterfaceLuid = currentRow.InterfaceLuid;
    actualInterface.InterfaceIndex = currentRow.InterfaceIndex;
    result = GetIpInterfaceEntry(&actualInterface);

    if (result != NO_ERROR) {
      LOG(ERROR) << "Error looking up interface "
                 << "[INDEX] " << currentRow.InterfaceIndex << " "
                 << "[LUID] " << currentRow.InterfaceLuid.Value;
      r["metric"] = INTEGER(-1);
      r["mtu"] = INTEGER(-1);
    } else {
      r["metric"] = INTEGER(actualInterface.Metric + currentRow.Metric);

      // The actual value returned is a unsigned long, but cap it so it can be
      // displayed in the table.
      if (actualInterface.NlMtu >= MAXINT32 &&
          actualInterface.NlMtu <= MAXULONG32) {
        r["mtu"] = INTEGER(MAXINT32);
      } else {
        r["mtu"] = INTEGER(actualInterface.NlMtu);
      }
    }

    if (addrFamily == AF_INET6) {
      std::vector<char> buffer(INET6_ADDRSTRLEN);

      // These are all technically "on-link" addresses according to
      // `route print -6`.
      r["type"] = "local";
      auto ipAddress = currentRow.DestinationPrefix.Prefix.Ipv6.sin6_addr;
      auto gateway = currentRow.NextHop.Ipv6.sin6_addr;

      InetNtopA(addrFamily, (PVOID)&ipAddress, buffer.data(), buffer.size());
      r["destination"] = SQL_TEXT(buffer.data());
      InetNtopA(addrFamily, (PVOID)&gateway, buffer.data(), buffer.size());
      r["gateway"] = SQL_TEXT(buffer.data());
    } else if (addrFamily == AF_INET) {
      std::vector<char> buffer(INET_ADDRSTRLEN);
      auto ipAddress = currentRow.DestinationPrefix.Prefix.Ipv4.sin_addr;
      auto gateway = currentRow.NextHop.Ipv4.sin_addr;

      InetNtopA(addrFamily, (PVOID)&ipAddress, buffer.data(), buffer.size());
      r["destination"] = SQL_TEXT(buffer.data());
      buffer.clear();

      // The software loopback is not returned by GetAdaptersInfo, so any
      // lookups into that index must be skipped and default values set.
      IP_ADAPTER_INFO actualAdapter;
      if (currentRow.InterfaceIndex != 1) {
        try {
          actualAdapter = adapters.at(currentRow.InterfaceIndex);
          interfaceIpAddress = actualAdapter.IpAddressList.IpAddress.String;
          r["gateway"] = SQL_TEXT(actualAdapter.GatewayList.IpAddress.String);
        } catch (const std::out_of_range& oor) {
          LOG(ERROR) << "Error looking up interface "
                     << currentRow.InterfaceIndex;
          LOG(ERROR) << oor.what();
        }
      } else {
        interfaceIpAddress = "127.0.0.1";
        InetNtopA(addrFamily, (PVOID)&gateway, buffer.data(), buffer.size());
        r["gateway"] = SQL_TEXT(buffer.data());
        buffer.clear();
      }
      r["type"] = currentRow.Loopback ? "local" : "remote";
    }
    r["interface"] = SQL_TEXT(interfaceIpAddress);
    r["netmask"] = INTEGER(currentRow.DestinationPrefix.PrefixLength);
    // TODO: implement routes flags
    r["flags"] = SQL_TEXT("-1");

    results.push_back(r);
  }

  // Cleanup
  FreeMibTable(ipTable);

  return results;
}
}
}
