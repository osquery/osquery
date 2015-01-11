/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>
#include <iomanip>

#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>

#ifdef __linux__
#include <linux/if_link.h>
#include <sys/ioctl.h>
#endif

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
  if (addr->ifa_addr != nullptr) {
    r["address"] = ipAsString((struct sockaddr *)addr->ifa_addr);
  }

  if (addr->ifa_netmask != nullptr) {
    r["mask"] = ipAsString((struct sockaddr *)addr->ifa_netmask);
  }

  // The destination address is used for either a broadcast or PtP address.
  if (addr->ifa_dstaddr != nullptr) {
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
  Row r;
  r["interface"] = std::string(addr->ifa_name);
  r["mac"] = macAsString(addr);

  if (addr->ifa_data != nullptr) {
#ifdef __linux__
    // Linux/Netlink interface details parsing.
    auto ifd = (struct rtnl_link_stats *)addr->ifa_data;
    r["ipackets"] = BIGINT_FROM_UINT32(ifd->rx_packets);
    r["opackets"] = BIGINT_FROM_UINT32(ifd->tx_packets);
    r["ibytes"] = BIGINT_FROM_UINT32(ifd->rx_bytes);
    r["obytes"] = BIGINT_FROM_UINT32(ifd->tx_bytes);
    r["ierrors"] = BIGINT_FROM_UINT32(ifd->rx_errors);
    r["oerrors"] = BIGINT_FROM_UINT32(ifd->tx_errors);

    // Get Linux physical properties for the AF_PACKET entry.
    int fd = socket(AF_INET, SOCK_DGRAM, 0); 
    if (fd >= 0) {
      struct ifreq ifr;
      strncpy(ifr.ifr_name, addr->ifa_name, IFNAMSIZ);
      if (ioctl(fd, SIOCGIFMTU, &ifr) >= 0) {
        r["mtu"] = BIGINT_FROM_UINT32(ifr.ifr_mtu);
      }

      if (ioctl(fd, SIOCGIFMETRIC, &ifr) >= 0) {
       r["metric"] = BIGINT_FROM_UINT32(ifr.ifr_metric);
      }

      if (ioctl(fd, SIOCGIFHWADDR, &ifr) >= 0) {
        r["type"] = INTEGER_FROM_UCHAR(ifr.ifr_hwaddr.sa_family); 
      }
    }

    r["last_change"] = "-1";
#else
    // Apple and FreeBSD interface details parsing.
    auto ifd = (struct if_data *)addr->ifa_data;
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
#endif
  }

  results.push_back(r);
}

QueryData genInterfaceAddresses(QueryContext &context) {
  QueryData results;

  struct ifaddrs *if_addrs, *if_addr;

  if (getifaddrs(&if_addrs) != 0) {
    return {};
  }

  for (if_addr = if_addrs; if_addr != NULL; if_addr = if_addr->ifa_next) {
    if (if_addr->ifa_addr->sa_family == AF_INET || if_addr->ifa_addr->sa_family == AF_INET6) {
      genAddressesFromAddr(if_addr, results);
    }
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
    if (if_addr->ifa_addr->sa_family != AF_INTERFACE) {
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
