/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
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
#else //  Apple || FreeBSD
#include <net/if_media.h>
#include <sys/sockio.h>
#endif
#include <sys/ioctl.h>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/networking/posix/interfaces.h>
#include <osquery/tables/networking/posix/utils.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>

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
  r["type"] = "unknown";
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
    auto const lflags_exp =
        tryTo<unsigned long int>(content.substr(2, content.size() - 3), 16);
    if (lflags_exp.isValue()) {
      flags |= lflags_exp.get() & sysfsFlags;
    }
  }
}
#else //  Apple || FreeBSD
// Based on IFM_SUBTYPE_ETHERNET_DESCRIPTIONS in if_media.h
static int get_linkspeed(int ifm_subtype) {
  switch (ifm_subtype) {
  case IFM_HPNA_1:
    return 1;
  case IFM_10_T:
  case IFM_10_2:
  case IFM_10_5:
  case IFM_10_STP:
  case IFM_10_FL:
    return 10;
  case IFM_100_TX:
  case IFM_100_FX:
  case IFM_100_T4:
  case IFM_100_VG:
  case IFM_100_T2:
    return 100;
  case IFM_1000_SX:
  case IFM_1000_LX:
  case IFM_1000_CX:
  case IFM_1000_T:
    return 1'000;
  case IFM_2500_T:
    return 2'500;
  case IFM_5000_T:
    return 5'000;
  case IFM_10G_SR:
  case IFM_10G_LR:
  case IFM_10G_CX4:
  case IFM_10G_T:
    return 10'000;
  }
  return 0;
}

#endif

void genDetailsFromAddr(const struct ifaddrs* addr,
                        QueryData& results,
                        QueryContext& context) {
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
      struct ifreq ifr = {};
      auto ifa_name_length = strlen(addr->ifa_name);
      snprintf(ifr.ifr_name,
               std::min<size_t>(ifa_name_length + 1, IFNAMSIZ),
               "%s",
               addr->ifa_name);
      if (ioctl(fd, SIOCGIFMTU, &ifr) >= 0) {
        r["mtu"] = BIGINT_FROM_UINT32(ifr.ifr_mtu);
      }

      if (ioctl(fd, SIOCGIFMETRIC, &ifr) >= 0) {
        r["metric"] = BIGINT_FROM_UINT32(ifr.ifr_metric);
      }

      if (ioctl(fd, SIOCGIFHWADDR, &ifr) >= 0) {
        r["type"] = INTEGER_FROM_UCHAR(ifr.ifr_hwaddr.sa_family);
      }

      r["link_speed"] = "0";
      if (context.isColumnUsed("link_speed")) {
        struct ethtool_cmd cmd;
        ifr.ifr_data = reinterpret_cast<char*>(&cmd);
        cmd.cmd = ETHTOOL_GSET;

        if (ioctl(fd, SIOCETHTOOL, &ifr) >= 0) {
          auto speed = ethtool_cmd_speed(&cmd);

          if (speed != std::numeric_limits<uint32_t>::max()) {
            r["link_speed"] = BIGINT_FROM_UINT32(speed);
          }
        }
      }
      struct ethtool_drvinfo drvInfo;
      ifr.ifr_data = reinterpret_cast<char*>(&drvInfo);
      drvInfo.cmd = ETHTOOL_GDRVINFO;

      if (ioctl(fd, SIOCETHTOOL, &ifr) >= 0) {
        r["pci_slot"] = drvInfo.bus_info;
      } else {
        r["pci_slot"] = "-1";
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
    r["link_speed"] = "0";
    if (context.isColumnUsed("link_speed")) {
      int fd = socket(AF_INET, SOCK_DGRAM, 0);
      if (fd >= 0) {
        struct ifmediareq ifmr = {};
        auto ifa_name_length = strlen(addr->ifa_name);
        snprintf(ifmr.ifm_name,
                 std::min<size_t>(ifa_name_length + 1, IFNAMSIZ),
                 "%s",
                 addr->ifa_name);
        if (ioctl(fd, SIOCGIFMEDIA, &ifmr) >= 0) {
          if (IFM_TYPE(ifmr.ifm_active) == IFM_ETHER) {
            int ifmls = get_linkspeed(IFM_SUBTYPE(ifmr.ifm_active));
            if (ifmls > 0) {
              r["link_speed"] = BIGINT_FROM_UINT32(ifmls);
            }
          }
        }
        close(fd);
      }
    }
#endif // Apple and FreeBSD interface details parsing.

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

    genDetailsFromAddr(if_addr, results, context);
  }

  freeifaddrs(if_addrs);
  return results;
}
} // namespace tables
} // namespace osquery
