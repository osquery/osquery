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
  auto freeMem = [](auto ptr) { free(ptr); };
  using ip_addr_info_t =
      std::unique_ptr<IP_ADAPTER_ADDRESSES, decltype(freeMem)>;

  QueryData results;

  DWORD bufLen = kWorkingBufferSize;
  auto it = 0;
  size_t ret;
  auto family = AF_UNSPEC;
  auto flags = GAA_FLAG_INCLUDE_PREFIX;

  ip_addr_info_t adapterAddrs(nullptr, freeMem);
  do {
    adapterAddrs.reset(static_cast<PIP_ADAPTER_ADDRESSES>(malloc(bufLen)));
    ret = GetAdaptersAddresses(
        family, flags, nullptr, adapterAddrs.get(), &bufLen);
    it++;
  } while (ret == ERROR_BUFFER_OVERFLOW && it < kMaxBufferAllocRetries);

  if (ret != NO_ERROR) {
    return results;
  }

  const IP_ADAPTER_ADDRESSES* currAddrs = adapterAddrs.get();
  while (currAddrs != nullptr) {
    const std::wstring name(currAddrs->FriendlyName);
    const IP_ADAPTER_UNICAST_ADDRESS* ipaddr =
        adapterAddrs->FirstUnicastAddress;
    while (ipaddr != nullptr) {
      Row r;
      r["interface"] = std::string(name.begin(), name.end());
      if (ipaddr->Address.lpSockaddr->sa_family == AF_INET) {
        auto addrBuff = std::make_unique<char[]>(INET_ADDRSTRLEN);
        inet_ntop(AF_INET,
                  &((sockaddr_in*)ipaddr->Address.lpSockaddr)->sin_addr,
                  addrBuff.get(),
                  INET_ADDRSTRLEN);
        r["address"] = addrBuff.get();
      } else if (ipaddr->Address.lpSockaddr->sa_family == AF_INET6) {
        auto addrBuf = std::make_unique<char[]>(INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6,
                  &((sockaddr_in6*)ipaddr->Address.lpSockaddr)->sin6_addr,
                  addrBuf.get(),
                  INET6_ADDRSTRLEN);
        r["address"] = addrBuf.get();
      }
      results.emplace_back(r);
      ipaddr = ipaddr->Next;
    }
    currAddrs = currAddrs->Next;
  }
  return results;
}
} // namespace tables
} // namespace osquery