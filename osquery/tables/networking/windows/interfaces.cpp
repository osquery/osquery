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
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

const auto kMaxBufferAllocRetries = 3;
const auto kWorkingBufferSize = 15000;
const auto kFreeMem = [](auto ptr) { free(ptr); };

Status getAdapters(std::vector<IP_ADAPTER_ADDRESSES>& adapterSet) {
  DWORD buffSize = kWorkingBufferSize;
  auto alloc_attempts = 0;
  size_t alloc_result = 0;
  const auto addrFamily = AF_UNSPEC;
  const auto addrFlags =
      GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
  std::unique_ptr<IP_ADAPTER_ADDRESSES, decltype(kFreeMem)> adapters(nullptr,
                                                                     kFreeMem);

  // Buffer size can change between the query and malloc (if adapters are
  // added/removed), so shenanigans are required
  do {
    adapters.reset(static_cast<PIP_ADAPTER_ADDRESSES>(malloc(buffSize)));
    if (adapters == nullptr) {
      return Status(1, "Error allocating buffer to receive adapters");
    }
    alloc_result = GetAdaptersAddresses(
        addrFamily, addrFlags, nullptr, adapters.get(), &buffSize);
    alloc_attempts++;
  } while (alloc_result == ERROR_BUFFER_OVERFLOW &&
           alloc_attempts < kMaxBufferAllocRetries);
  if (alloc_result != NO_ERROR) {
    return Status(1, "Error allocating buffer to receive adapters");
  }

  const IP_ADAPTER_ADDRESSES* currAdapter = adapters.get();
  while (currAdapter != nullptr) {
    adapterSet.push_back(*currAdapter);
    currAdapter = currAdapter->Next;
  }
  return Status();
}

Status genInterfaceDetail(const IP_ADAPTER_ADDRESSES& adapter, Row& r) {
  r["interface"] = INTEGER(adapter.IfIndex);
  r["mtu"] = INTEGER(adapter.Mtu);
  r["type"] = INTEGER(adapter.IfType);

  std::wstring wideHolder = std::wstring(adapter.Description);
  auto description = std::string(wideHolder.begin(), wideHolder.end());
  r["description"] = description;

  std::vector<std::string> toks;
  for (size_t i = 0; i < adapter.PhysicalAddressLength; i++) {
    std::stringstream ss;
    ss << std::hex;
    ss << static_cast<unsigned int>(adapter.PhysicalAddress[i]);
    auto s = ss.str();
    if (s.size() < static_cast<unsigned int>(2)) {
      s = "0" + s;
    }
    toks.push_back(s);
  }
  r["mac"] = osquery::join(toks, ":");
  r["flags"] = INTEGER(adapter.Flags);
  r["metric"] = INTEGER(adapter.Ipv4Metric);

  // Issue #2907: These values still require some work to get
  r["ipackets"] = BIGINT("-1");
  r["opackets"] = BIGINT("-1");
  r["ibytes"] = BIGINT("-1");
  r["obytes"] = BIGINT("-1");
  r["ierrors"] = BIGINT("-1");
  r["oerrors"] = BIGINT("-1");
  r["idrops"] = BIGINT("-1");
  r["odrops"] = BIGINT("-1");
  r["collisions"] = BIGINT("-1");
  r["last_change"] = BIGINT("-1");

  // Grab the addition Windows schema values from WMI
  Status s;
  long lPlaceHolder = 0;
  unsigned __int64 ulPlaceHolder = 0;
  bool bPlaceHolder;
  std::vector<std::string> vPlaceHolder;
  auto query =
      "SELECT * FROM Win32_NetworkAdapter WHERE "
      "InterfaceIndex = " +
      r["interface"];
  WmiRequest req(query);
  if (req.getStatus().ok()) {
    auto& results = req.results();
    if (!results.empty()) {
      results[0].GetString("NetConnectionID", r["connection_id"]);
      results[0].GetLong("NetConnectionStatus", lPlaceHolder);
      r["connection_status"] = INTEGER(lPlaceHolder);
      results[0].GetBool("NetEnabled", bPlaceHolder);
      r["enabled"] = INTEGER(bPlaceHolder);
      results[0].GetBool("PhysicalAdapter", bPlaceHolder);
      r["physical_adapter"] = INTEGER(bPlaceHolder);
      results[0].GetUnsignedLongLong("Speed", ulPlaceHolder);
      r["speed"] = INTEGER(ulPlaceHolder);
    } else {
      s = Status(1, "Failed to enumerate extended interface details");
    }
  }
  query =
      "SELECT * FROM win32_networkadapterconfiguration WHERE "
      "InterfaceIndex = " +
      r["interface"];

  WmiRequest irequest(query);
  if (irequest.getStatus().ok()) {
    auto& iresults = irequest.results();
    if (!iresults.empty()) {
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
    } else {
      s = Status(1, "Failed to enumerate extended interface details");
    }
  }
  return s;
}

QueryData genInterfaceDetails(QueryContext& context) {
  QueryData results;
  std::vector<IP_ADAPTER_ADDRESSES> adapters;

  auto s = getAdapters(adapters);
  if (!s.ok()) {
    LOG(WARNING) << s.getMessage();
    return results;
  }

  for (const auto& adapter : adapters) {
    Row r;
    auto s = genInterfaceDetail(adapter, r);
    if (s.ok()) {
      results.push_back(r);
    } else {
      // The only failure we might expect is the extended details enumeration
      // in which we do not care to WARN
      LOG(INFO) << s.getMessage();
    }
  }

  return results;
}

void genInterfaceAddress(const IP_ADAPTER_UNICAST_ADDRESS* ipaddr, Row& r) {
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

    inet_ntop(
        AF_INET,
        &reinterpret_cast<sockaddr_in*>(ipaddr->Address.lpSockaddr)->sin_addr,
        addrBuff,
        INET_ADDRSTRLEN);
    r["address"] = addrBuff;
  } else if (ipaddr->Address.lpSockaddr->sa_family == AF_INET6) {
    in6_addr netmask;
    memset(&netmask, 0x0, sizeof(netmask));
    for (long i = ipaddr->OnLinkPrefixLength, j = 0; i > 0; i -= 8, ++j) {
      netmask.s6_addr[j] = i >= 8 ? 0xff : (ULONG)((0xffU << (8 - i)));
    }

    char addrBuff[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, &netmask, addrBuff, INET6_ADDRSTRLEN);
    r["mask"] = addrBuff;

    inet_ntop(
        AF_INET6,
        &reinterpret_cast<sockaddr_in6*>(ipaddr->Address.lpSockaddr)->sin6_addr,
        addrBuff,
        INET6_ADDRSTRLEN);
    r["address"] = addrBuff;
  }
}

QueryData genInterfaceAddresses(QueryContext& context) {
  QueryData results;
  std::vector<IP_ADAPTER_ADDRESSES> adapters;

  auto s = getAdapters(adapters);
  if (!s.ok()) {
    LOG(WARNING) << s.getMessage();
    return results;
  }

  for (const auto& adapter : adapters) {
    std::wstring wsAdapterName = std::wstring(adapter.FriendlyName);
    auto adapterName = std::string(wsAdapterName.begin(), wsAdapterName.end());

    const IP_ADAPTER_UNICAST_ADDRESS* ipaddr = adapter.FirstUnicastAddress;
    while (ipaddr != nullptr) {
      Row r;
      r["interface"] = SQL_TEXT(adapter.IfIndex);
      r["friendly_name"] = adapterName;
      genInterfaceAddress(ipaddr, r);
      ipaddr = ipaddr->Next;
      results.push_back(r);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
