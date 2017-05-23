/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

// clang-format off
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
// clang-format on

#include <boost/algorithm/string/join.hpp>

#include <osquery/core.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

auto kMaxBufferAllocRetries = 3;
auto kWorkingBufferSize = 15000;

QueryData genInterfaceDetails(QueryContext& context) {
  QueryData results_data;
  WmiRequest request("SELECT * FROM Win32_NetworkAdapter");
  if (request.getStatus().ok()) {
    std::vector<WmiResultItem>& results = request.results();
    for (const auto& result : results) {
      Row r;
      long lPlaceHolder;
      bool bPlaceHolder;
      std::vector<std::string> vPlaceHolder;
      unsigned __int64 ulPlaceHolder;

      result.GetString("AdapterType", r["type"]);
      result.GetString("Description", r["description"]);
      result.GetLong("InterfaceIndex", lPlaceHolder);
      r["interface"] = INTEGER(lPlaceHolder);
      result.GetString("MACAddress", r["mac"]);
      result.GetString("Manufacturer", r["manufacturer"]);
      result.GetString("NetConnectionID", r["connection_id"]);
      result.GetLong("NetConnectionStatus", lPlaceHolder);
      r["connection_status"] = INTEGER(lPlaceHolder);
      result.GetBool("NetEnabled", bPlaceHolder);
      r["enabled"] = INTEGER(bPlaceHolder);
      result.GetBool("PhysicalAdapter", bPlaceHolder);
      r["physical_adapter"] = INTEGER(bPlaceHolder);
      result.GetUnsignedLongLong("Speed", ulPlaceHolder);
      r["speed"] = INTEGER(ulPlaceHolder);

      std::string query =
          "SELECT * FROM win32_networkadapterconfiguration WHERE "
          "InterfaceIndex = " +
          r["interface"];

      WmiRequest irequest(query);
      if (irequest.getStatus().ok()) {
        std::vector<WmiResultItem>& iresults = irequest.results();

        iresults[0].GetBool("DHCPEnabled", bPlaceHolder);
        r["dhcp_enabled"] = INTEGER(bPlaceHolder);
        iresults[0].GetString("DHCPLeaseExpires", r["dhcp_lease_expires"]);
        iresults[0].GetString("DHCPLeaseObtained", r["dhcp_lease_obtained"]);
        iresults[0].GetString("DHCPServer", r["dhcp_server"]);
        iresults[0].GetString("DNSDomain", r["dns_domain"]);
        iresults[0].GetVectorOfStrings("DNSDomainSuffixSearchOrder",
                                       vPlaceHolder);
        r["dns_domain_suffix_search_order"] =
            SQL_TEXT(boost::algorithm::join(vPlaceHolder, ", "));
        iresults[0].GetString("DNSHostName", r["dns_host_name"]);
        iresults[0].GetVectorOfStrings("DNSServerSearchOrder", vPlaceHolder);
        r["dns_server_search_order"] =
            SQL_TEXT(boost::algorithm::join(vPlaceHolder, ", "));
      }
      results_data.push_back(r);
    }
  }
  return results_data;
}

QueryData genInterfaceAddresses(QueryContext& context) {
  QueryData results;
  DWORD buffSize = kWorkingBufferSize;
  auto alloc_attempts = 0;
  size_t alloc_result;
  const auto addrFamily = AF_UNSPEC;
  const auto addrFlags =
      GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
  const auto freeMem = [](auto ptr) { free(ptr); };
  std::unique_ptr<IP_ADAPTER_ADDRESSES, decltype(freeMem)> adapters(nullptr,
                                                                    freeMem);

  // Buffer size can change between the query and malloc (if adapters are
  // added/removed), so shenanigans are required
  do {
    adapters.reset(static_cast<PIP_ADAPTER_ADDRESSES>(malloc(buffSize)));
    if (adapters == nullptr) {
      return results;
    }
    alloc_result = GetAdaptersAddresses(
        addrFamily, addrFlags, nullptr, adapters.get(), &buffSize);
    alloc_attempts++;
  } while (alloc_result == ERROR_BUFFER_OVERFLOW &&
           alloc_attempts < kMaxBufferAllocRetries);
  if (alloc_result != NO_ERROR) {
    return results;
  }

  const IP_ADAPTER_ADDRESSES* currAdapter = adapters.get();
  while (currAdapter != nullptr) {
    std::wstring wsAdapterName = std::wstring(currAdapter->FriendlyName);
    std::string adapterName =
        std::string(wsAdapterName.begin(), wsAdapterName.end());

    const IP_ADAPTER_UNICAST_ADDRESS* ipaddr = currAdapter->FirstUnicastAddress;
    while (ipaddr != nullptr) {
      Row r;
      r["interface"] = adapterName;

      switch (ipaddr->SuffixOrigin) {
      case IpSuffixOriginManual:
        r["type"] = "manual";
        break;
      case IpSuffixOriginDhcp:
        r["type"] = "dhcp";
        break;
      case IpSuffixOriginLinkLayerAddress:
      case IpSuffixOriginRandom:
        r["type"] = "auto";
        break;
      default:
        r["type"] = "unknown";
      }

      if (ipaddr->Address.lpSockaddr->sa_family == AF_INET) {
        ULONG mask;
        ConvertLengthToIpv4Mask(ipaddr->OnLinkPrefixLength, &mask);
        in_addr maskAddr;
        maskAddr.s_addr = mask;

        char addrBuff[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &maskAddr, addrBuff, INET_ADDRSTRLEN);
        r["mask"] = addrBuff;

        inet_ntop(AF_INET,
                  &reinterpret_cast<sockaddr_in*>(ipaddr->Address.lpSockaddr)
                       ->sin_addr,
                  addrBuff,
                  INET_ADDRSTRLEN);
        r["address"] = addrBuff;
      } else if (ipaddr->Address.lpSockaddr->sa_family == AF_INET6) {
        in6_addr netmask;
        memset(&netmask, 0x0, sizeof(netmask));
        for (long i = ipaddr->OnLinkPrefixLength, j = 0; i > 0; i -= 8, ++j)
          netmask.s6_addr[j] = i >= 8 ? 0xff : (ULONG)((0xffU << (8 - i)));

        char addrBuff[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, &netmask, addrBuff, INET6_ADDRSTRLEN);
        r["mask"] = addrBuff;

        inet_ntop(AF_INET6,
                  &reinterpret_cast<sockaddr_in6*>(ipaddr->Address.lpSockaddr)
                       ->sin6_addr,
                  addrBuff,
                  INET6_ADDRSTRLEN);
        r["address"] = addrBuff;
      }
      results.emplace_back(r);
      ipaddr = ipaddr->Next;
    }
    currAdapter = currAdapter->Next;
  }
  return results;
}
} // namespace tables
} // namespace osquery
