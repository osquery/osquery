/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iomanip>
#include <sstream>

// Maintain the order of includes (ifaddrs after if).
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>

#ifdef __linux__
#include <limits>
#include <linux/ethtool.h>
#include <linux/if_link.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#endif

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/networking/utils.h"

namespace osquery {
namespace tables {

#ifdef __linux__
const size_t sysfsFlags = IFF_UP | IFF_DEBUG | IFF_NOTRAILERS | IFF_NOARP |
                          IFF_PROMISC | IFF_ALLMULTI | IFF_MULTICAST |
                          IFF_PORTSEL | IFF_AUTOMEDIA | IFF_DYNAMIC;
#endif

// Functions for safe sign-extension
std::basic_string<char> INTEGER_FROM_UCHAR(unsigned char x) {
  return INTEGER(static_cast<uint16_t>(x));
}

std::basic_string<char> BIGINT_FROM_UINT32(uint32_t x) {
  return BIGINT(static_cast<uint64_t>(x));
}

void genAddressesFromAddr(const struct ifaddrs* addr, QueryData& results) {
  std::string dest_address;
  Row r;
  r["interface"] = std::string(addr->ifa_name);

  // Address and mask will appear every time.
  if (addr->ifa_addr != nullptr) {
    r["address"] = ipAsString(static_cast<struct sockaddr*>(addr->ifa_addr));
  }

  if (addr->ifa_netmask != nullptr) {
    r["mask"] = ipAsString(static_cast<struct sockaddr*>(addr->ifa_netmask));
  }

  // The destination address is used for either a broadcast or PtP address.
  if (addr->ifa_dstaddr != nullptr) {
    dest_address = ipAsString(static_cast<struct sockaddr*>(addr->ifa_dstaddr));
    if ((addr->ifa_flags & IFF_BROADCAST) == IFF_BROADCAST) {
      r["broadcast"] = dest_address;
    } else {
      r["point_to_point"] = dest_address;
    }
  }

  results.push_back(r);
}

#ifdef __linux__
static inline void flagsFromSysfs(const std::string& name, size_t& flags) {
  auto flags_path = "/sys/class/net/" + name + "/flags";
  std::string content;
  if (!pathExists(flags_path) || !readFile(flags_path, content) ||
      content.size() <= 3) {
    return;
  }

  // This will take the form, 0xVALUE\n.
  if (content[0] == '0' && content[1] == 'x') {
    unsigned long int lflags = 0;
    if (safeStrtoul(content.substr(2, content.size() - 3), 16, lflags)) {
      flags |= lflags & sysfsFlags;
    }
  }
}
#endif

void genDetailsFromAddr(const struct ifaddrs* addr, QueryData& results) {
  Row r;
  if (addr->ifa_name != nullptr) {
    r["interface"] = std::string(addr->ifa_name);
  } else {
    r["interface"] = "";
  }
  r["mac"] = macAsString(addr);

  size_t flags = addr->ifa_flags;

  if (addr->ifa_data != nullptr && addr->ifa_name != nullptr) {
#ifdef __linux__
    // Linux/Netlink interface details parsing.
    auto ifd = static_cast<struct rtnl_link_stats*>(addr->ifa_data);
    r["mtu"] = "0";
    r["metric"] = "0";
    r["type"] = "0";
    r["ipackets"] = BIGINT_FROM_UINT32(ifd->rx_packets);
    r["opackets"] = BIGINT_FROM_UINT32(ifd->tx_packets);
    r["ibytes"] = BIGINT_FROM_UINT32(ifd->rx_bytes);
    r["obytes"] = BIGINT_FROM_UINT32(ifd->tx_bytes);
    r["ierrors"] = BIGINT_FROM_UINT32(ifd->rx_errors);
    r["oerrors"] = BIGINT_FROM_UINT32(ifd->tx_errors);
    r["idrops"] = BIGINT_FROM_UINT32(ifd->rx_dropped);
    r["odrops"] = BIGINT_FROM_UINT32(ifd->tx_dropped);
    r["collisions"] = BIGINT_FROM_UINT32(ifd->collisions);
    // Get Linux physical properties for the AF_PACKET entry.
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
      struct ifreq ifr;
      memcpy(ifr.ifr_name, addr->ifa_name, IFNAMSIZ);
      if (ioctl(fd, SIOCGIFMTU, &ifr) >= 0) {
        r["mtu"] = BIGINT_FROM_UINT32(ifr.ifr_mtu);
      }

      if (ioctl(fd, SIOCGIFMETRIC, &ifr) >= 0) {
        r["metric"] = BIGINT_FROM_UINT32(ifr.ifr_metric);
      }

      if (ioctl(fd, SIOCGIFHWADDR, &ifr) >= 0) {
        r["type"] = INTEGER_FROM_UCHAR(ifr.ifr_hwaddr.sa_family);
      }

      struct ethtool_cmd cmd;
      ifr.ifr_data = reinterpret_cast<char*>(&cmd);
      cmd.cmd = ETHTOOL_GSET;

      if (ioctl(fd, SIOCETHTOOL, &ifr) >= 0) {
        auto speed = ethtool_cmd_speed(&cmd);

        if (speed != std::numeric_limits<uint32_t>::max()) {
          r["link_speed"] = BIGINT_FROM_UINT32(speed);
        }
      }

      close(fd);
    }

    // Filter out sysfs flags.
    flags &= ~sysfsFlags;

    // Populate sysfs flags from sysfs.
    flagsFromSysfs(r["interface"], flags);

    // Last change is not implemented in Linux.
    r["last_change"] = "-1";
#else
    // Apple and FreeBSD interface details parsing.
    auto ifd = (struct if_data*)addr->ifa_data;
    r["type"] = INTEGER_FROM_UCHAR(ifd->ifi_type);
    r["mtu"] = BIGINT_FROM_UINT32(ifd->ifi_mtu);
    r["metric"] = BIGINT_FROM_UINT32(ifd->ifi_metric);
    r["ipackets"] = BIGINT_FROM_UINT32(ifd->ifi_ipackets);
    r["opackets"] = BIGINT_FROM_UINT32(ifd->ifi_opackets);
    r["ibytes"] = BIGINT_FROM_UINT32(ifd->ifi_ibytes);
    r["obytes"] = BIGINT_FROM_UINT32(ifd->ifi_obytes);
    r["ierrors"] = BIGINT_FROM_UINT32(ifd->ifi_ierrors);
    r["oerrors"] = BIGINT_FROM_UINT32(ifd->ifi_oerrors);
    r["idrops"] = BIGINT_FROM_UINT32(ifd->ifi_iqdrops);
    r["odrops"] = INTEGER(0);
    r["collisions"] = BIGINT_FROM_UINT32(ifd->ifi_collisions);
    r["last_change"] = BIGINT_FROM_UINT32(ifd->ifi_lastchange.tv_sec);
#endif
    r["flags"] = INTEGER(flags);
  }

  results.push_back(r);
}

QueryData genInterfaceAddresses(QueryContext& context) {
  QueryData results;

  struct ifaddrs* if_addrs = nullptr;
  struct ifaddrs* if_addr = nullptr;
  if (getifaddrs(&if_addrs) != 0 || if_addrs == nullptr) {
    return {};
  }

  for (if_addr = if_addrs; if_addr != nullptr; if_addr = if_addr->ifa_next) {
    if (if_addr->ifa_addr == nullptr) {
      continue;
    }
    if (if_addr->ifa_addr->sa_family == AF_INET ||
        if_addr->ifa_addr->sa_family == AF_INET6) {
      genAddressesFromAddr(if_addr, results);
    }
  }

  freeifaddrs(if_addrs);
  return results;
}

QueryData genInterfaceDetails(QueryContext& context) {
  QueryData results;

  struct ifaddrs* if_addrs = nullptr;
  struct ifaddrs* if_addr = nullptr;
  if (getifaddrs(&if_addrs) != 0 || if_addrs == nullptr) {
    return {};
  }

  for (if_addr = if_addrs; if_addr != nullptr; if_addr = if_addr->ifa_next) {
    if (if_addr->ifa_addr != nullptr &&
        if_addr->ifa_addr->sa_family != AF_INTERFACE) {
      // This interface entry does not describe the link details.
      continue;
    }

    genDetailsFromAddr(if_addr, results);
  }

  freeifaddrs(if_addrs);
  return results;
}
} // namespace tables
} // namespace osquery
