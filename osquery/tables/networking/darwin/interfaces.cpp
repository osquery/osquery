// Copyright 2004-present Facebook. All Rights Reserved.

#include <sstream>
#include <iomanip>

#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/networking/utils.h"

namespace osquery {
namespace tables {

// Macros for safe sign-extension
#define INTEGER_FROM_UCHAR(x) INTEGER((uint16_t)x);
#define BIGINT_FROM_UINT32(x) BIGINT((uint64_t)x);

void genAddressesFromAddr(const struct ifaddrs *addr, QueryData &results) {
  std::string dest_address;
  Row r;
  r["interface"] = std::string(addr->ifa_name);

  // Address and mask will appear everytime.
  r["address"] = ipAsString((struct sockaddr *)addr->ifa_addr);
  r["mask"] = ipAsString((struct sockaddr *)addr->ifa_netmask);

  // The destination address is used for either a broadcast or PtP address.
  if (addr->ifa_dstaddr != NULL) {
    dest_address = ipAsString((struct sockaddr *)addr->ifa_dstaddr);
    if ((addr->ifa_flags & IFF_BROADCAST) == IFF_BROADCAST) {
      r["broadcast"] = dest_address;
    } else {
      r["point_to_point"] = dest_address;
    }
  }

  results.push_back(r);
}

void genDetailsFromAddr(const struct ifaddrs *addr, QueryData &results) {
  struct if_data *ifd;

  Row r;
  r["interface"] = std::string(addr->ifa_name);
  r["mac"] = macAsString(addr);

  ifd = (struct if_data *)addr->ifa_data;
  r["type"] = INTEGER_FROM_UCHAR(ifd->ifi_type);
  r["mtu"] = BIGINT_FROM_UINT32(ifd->ifi_mtu);
  r["metric"] = BIGINT_FROM_UINT32(ifd->ifi_metric);
  r["ipackets"] = BIGINT_FROM_UINT32(ifd->ifi_ipackets);
  r["opackets"] = BIGINT_FROM_UINT32(ifd->ifi_opackets);
  r["ibytes"] = BIGINT_FROM_UINT32(ifd->ifi_ibytes);
  r["obytes"] = BIGINT_FROM_UINT32(ifd->ifi_obytes);
  r["ierrors"] = BIGINT_FROM_UINT32(ifd->ifi_ierrors);
  r["oerrors"] = BIGINT_FROM_UINT32(ifd->ifi_oerrors);
  r["last_change"] = BIGINT_FROM_UINT32(ifd->ifi_lastchange.tv_sec);
  results.push_back(r);
}

QueryData genInterfaceAddresses(QueryContext &context) {
  QueryData results;

  struct ifaddrs *if_addrs, *if_addr;

  if (getifaddrs(&if_addrs) != 0) {
    return {};
  }

  for (if_addr = if_addrs; if_addr != NULL; if_addr = if_addr->ifa_next) {
    if (if_addr->ifa_addr->sa_family == AF_LINK) {
      continue;
    }

    genAddressesFromAddr(if_addr, results);
  }

  freeifaddrs(if_addrs);
  return results;
}

QueryData genInterfaceDetails(QueryContext &context) {
  QueryData results;

  struct ifaddrs *if_addrs, *if_addr;

  if (getifaddrs(&if_addrs) != 0) {
    return {};
  }

  for (if_addr = if_addrs; if_addr != NULL; if_addr = if_addr->ifa_next) {
    if (if_addr->ifa_addr->sa_family != AF_LINK) {
      // This interface entry does not describe the link details.
      continue;
    }

    genDetailsFromAddr(if_addr, results);
  }

  freeifaddrs(if_addrs);
  return results;
}
}
}
