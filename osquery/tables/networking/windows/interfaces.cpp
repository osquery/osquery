/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

// clang-format off
#include <osquery/utils/system/system.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
// clang-format on

#include <boost/algorithm/string/join.hpp>

#include <osquery/core/core.h>
#include <osquery/logger/logger.h>
#include <osquery/core/tables.h>

#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/tryto.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {

const auto kMaxBufferAllocRetries = 3;
const auto kWorkingBufferSize = 15000;

void genInterfaceDetail(const IP_ADAPTER_ADDRESSES* adapter, Row& r) {
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
  auto query =
      "SELECT * FROM Win32_PerfRawData_Tcpip_NetworkInterface WHERE "
      "Name = \"" +
      r["description"] + "\"";

  const auto req1 = WmiRequest::CreateWmiRequest(query);
  if (req1 && req1->getStatus().ok()) {
    const auto& results = req1->results();
    if (!results.empty()) {
      std::string sPlaceHolder;

      results[0].GetString("PacketsReceivedPerSec", sPlaceHolder);
      r["ipackets"] =
          BIGINT(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));
      results[0].GetString("PacketsSentPerSec", sPlaceHolder);
      r["opackets"] =
          BIGINT(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));

      results[0].GetString("BytesReceivedPerSec", sPlaceHolder);
      r["ibytes"] =
          BIGINT(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));
      results[0].GetString("BytesSentPerSec", sPlaceHolder);
      r["obytes"] =
          BIGINT(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));

      results[0].GetString("PacketsReceivedErrors", sPlaceHolder);
      r["ierrors"] =
          BIGINT(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));
      results[0].GetString("PacketsOutboundErrors", sPlaceHolder);
      r["oerrors"] =
          BIGINT(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));

      results[0].GetString("PacketsReceivedDiscarded", sPlaceHolder);
      r["idrops"] =
          BIGINT(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));
      results[0].GetString("PacketsOutboundDiscarded", sPlaceHolder);
      r["odrops"] =
          BIGINT(tryTo<unsigned long long>(sPlaceHolder).takeOr(0ull));
    } else {
      LOG(INFO) << "Failed to retrieve network statistics for interface "
                << r["interface"];
    }
  }

  query =
      "SELECT * FROM Win32_NetworkAdapter WHERE "
      "InterfaceIndex = " +
      r["interface"];
  const auto req2 = WmiRequest::CreateWmiRequest(query);
  if (req2 && req2->getStatus().ok()) {
    const auto& results = req2->results();
    if (!results.empty()) {
      bool bPlaceHolder;
      long lPlaceHolder = 0;
      unsigned __int64 ullPlaceHolder = 0;
      results[0].GetString("Manufacturer", r["manufacturer"]);
      results[0].GetString("NetConnectionID", r["connection_id"]);
      results[0].GetLong("NetConnectionStatus", lPlaceHolder);
      r["connection_status"] = INTEGER(lPlaceHolder);
      results[0].GetBool("NetEnabled", bPlaceHolder);
      r["enabled"] = INTEGER(bPlaceHolder);
      results[0].GetBool("PhysicalAdapter", bPlaceHolder);
      r["physical_adapter"] = INTEGER(bPlaceHolder);
      results[0].GetString("ServiceName", r["service"]);
      results[0].GetUnsignedLongLong("Speed", ullPlaceHolder);
      r["speed"] = INTEGER(ullPlaceHolder);
    } else {
      LOG(INFO) << "Failed to retrieve physical state for interface "
                << r["interface"];
    }
  }

  query =
      "SELECT * FROM win32_networkadapterconfiguration WHERE "
      "InterfaceIndex = " +
      r["interface"];
  const auto req3 = WmiRequest::CreateWmiRequest(query);
  if (req3 && req3->getStatus().ok()) {
    const auto& results = req3->results();
    if (!results.empty()) {
      bool bPlaceHolder = false;
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
      LOG(INFO) << "Failed to retrieve DHCP and DNS information for interface "
                << r["interface"];
    }
  }
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
    genInterfaceDetail(currAdapter, r);
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
    auto adapterName = wstringToString(currAdapter->FriendlyName);
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
