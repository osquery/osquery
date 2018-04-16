/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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

Status genInterfaceDetail(const IP_ADAPTER_ADDRESSES* adapter, Row& r) {
  r["interface"] = INTEGER(adapter->IfIndex);
  r["mtu"] = INTEGER(adapter->Mtu);
  r["type"] = INTEGER(adapter->IfType);
  r["description"] = wstringToString(adapter->Description);

  std::vector<std::string> toks;
  for (size_t i = 0; i < adapter->PhysicalAddressLength; i++) {
    std::stringstream ss;
    ss << std::hex;
    ss << static_cast<unsigned int>(adapter->PhysicalAddress[i]);
    auto s = ss.str();
    if (s.size() < 2_sz) {
      s = '0' + s;
    }
    toks.push_back(s);
  }
  r["mac"] = osquery::join(toks, ":");
  r["flags"] = INTEGER(adapter->Flags);
  r["metric"] = INTEGER(adapter->Ipv4Metric);

  // TODO: These values will need an equivalent on Windows systems
  r["last_change"] = BIGINT("-1");
  r["collisions"] = BIGINT("-1");

  // Grab the remaining table values from WMI
  Status s;
  auto query =
      "SELECT * FROM Win32_PerfRawData_Tcpip_NetworkInterface WHERE "
      "Name = \"" +
      r["description"] + "\"";
  WmiRequest req1(query);
  if (req1.getStatus().ok()) {
    auto& results = req1.results();
    if (!results.empty()) {
      std::string sPlaceHolder;
      unsigned long long ullPlaceHolder = 0;

      results[0].GetString("PacketsReceivedPerSec", sPlaceHolder);
      safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
      r["ipackets"] = BIGINT(ullPlaceHolder);
      results[0].GetString("PacketsSentPerSec", sPlaceHolder);
      safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
      r["opackets"] = BIGINT(ullPlaceHolder);

      results[0].GetString("BytesReceivedPerSec", sPlaceHolder);
      safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
      r["ibytes"] = BIGINT(ullPlaceHolder);
      results[0].GetString("BytesSentPerSec", sPlaceHolder);
      safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
      r["obytes"] = BIGINT(ullPlaceHolder);

      results[0].GetString("PacketsReceivedErrors", sPlaceHolder);
      safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
      r["ierrors"] = BIGINT(ullPlaceHolder);
      results[0].GetString("PacketsOutboundErrors", sPlaceHolder);
      safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
      r["oerrors"] = BIGINT(ullPlaceHolder);

      results[0].GetString("PacketsReceivedDiscarded", sPlaceHolder);
      safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
      r["idrops"] = BIGINT(ullPlaceHolder);
      results[0].GetString("PacketsOutboundDiscarded", sPlaceHolder);
      safeStrtoull(sPlaceHolder, 10, ullPlaceHolder);
      r["odrops"] = BIGINT(ullPlaceHolder);
    } else {
      r["ipackets"] = BIGINT("-1");
      r["opackets"] = BIGINT("-1");
      r["ibytes"] = BIGINT("-1");
      r["obytes"] = BIGINT("-1");
      r["ierrors"] = BIGINT("-1");
      r["oerrors"] = BIGINT("-1");
      r["idrops"] = BIGINT("-1");
      r["odrops"] = BIGINT("-1");
      s = Status(1, "Failed to enumerate extended interface details");
    }
  }

  query =
      "SELECT * FROM Win32_NetworkAdapter WHERE "
      "InterfaceIndex = " +
      r["interface"];
  WmiRequest req2(query);
  if (req2.getStatus().ok()) {
    auto& results = req2.results();
    if (!results.empty()) {
      bool bPlaceHolder;
      long lPlaceHolder{0};
      unsigned __int64 ullPlaceHolder = 0;
      results[0].GetString("NetConnectionID", r["connection_id"]);
      results[0].GetLong("NetConnectionStatus", lPlaceHolder);
      r["connection_status"] = INTEGER(lPlaceHolder);
      results[0].GetBool("NetEnabled", bPlaceHolder);
      r["enabled"] = INTEGER(bPlaceHolder);
      results[0].GetBool("PhysicalAdapter", bPlaceHolder);
      r["physical_adapter"] = INTEGER(bPlaceHolder);
      results[0].GetUnsignedLongLong("Speed", ullPlaceHolder);
      r["speed"] = INTEGER(ullPlaceHolder);
    } else {
      s = Status(1, "Failed to enumerate extended interface details");
    }
  }

  query =
      "SELECT * FROM win32_networkadapterconfiguration WHERE "
      "InterfaceIndex = " +
      r["interface"];
  WmiRequest req3(query);
  if (req3.getStatus().ok()) {
    auto& results = req3.results();
    if (!results.empty()) {
      bool bPlaceHolder;
      std::vector<std::string> vPlaceHolder;
      results[0].GetBool("DHCPEnabled", bPlaceHolder);
      r["dhcp_enabled"] = INTEGER(bPlaceHolder);
      results[0].GetString("DHCPLeaseExpires", r["dhcp_lease_expires"]);
      results[0].GetString("DHCPLeaseObtained", r["dhcp_lease_obtained"]);
      results[0].GetString("DHCPServer", r["dhcp_server"]);
      results[0].GetString("DNSDomain", r["dns_domain"]);
      results[0].GetVectorOfStrings("DNSDomainSuffixSearchOrder", vPlaceHolder);
      r["dns_domain_suffix_search_order"] = osquery::join(vPlaceHolder, ", ");
      results[0].GetString("DNSHostName", r["dns_host_name"]);
      results[0].GetVectorOfStrings("DNSServerSearchOrder", vPlaceHolder);
      r["dns_server_search_order"] = osquery::join(vPlaceHolder, ", ");
    } else {
      s = Status(1, "Failed to enumerate extended interface details");
    }
  }
  return s;
}

QueryData genInterfaceDetails(QueryContext& context) {
  QueryData results;

  DWORD buffSize = kWorkingBufferSize;
  auto alloc_attempts = 0;
  size_t alloc_result = 0;
  const auto addrFamily = AF_UNSPEC;
  const auto addrFlags =
      GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
  std::unique_ptr<IP_ADAPTER_ADDRESSES> adapters(nullptr);

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
    Row r;
    auto s = genInterfaceDetail(currAdapter, r);
    if (!s.ok()) {
      // The only failure we might expect is the extended details enumeration
      // in which we do not care to WARN
      VLOG(1) << s.getMessage();
    }
    currAdapter = currAdapter->Next;
    results.push_back(r);
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

  DWORD buffSize = kWorkingBufferSize;
  auto alloc_attempts = 0;
  size_t alloc_result = 0;
  const auto addrFamily = AF_UNSPEC;
  const auto addrFlags =
      GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
  std::unique_ptr<IP_ADAPTER_ADDRESSES> adapters(nullptr);

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
    auto adapterName = std::string(wsAdapterName.begin(), wsAdapterName.end());

    const IP_ADAPTER_UNICAST_ADDRESS* ipaddr = currAdapter->FirstUnicastAddress;
    while (ipaddr != nullptr) {
      Row r;
      r["interface"] = SQL_TEXT(currAdapter->IfIndex);
      r["friendly_name"] = adapterName;
      genInterfaceAddress(ipaddr, r);
      ipaddr = ipaddr->Next;
      results.push_back(r);
    }
    currAdapter = currAdapter->Next;
  }
  return results;
}
} // namespace tables
} // namespace osquery
