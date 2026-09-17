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
#include <numeric>
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
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>

#ifdef __APPLE__
#include <Foundation/Foundation.h>
#include <SystemConfiguration/SCNetworkConfiguration.h>

#include <osquery/utils/conversions/darwin/cfstring.h>
#endif

namespace osquery {
namespace tables {

#ifdef __linux__
const size_t sysfsFlags = IFF_UP | IFF_DEBUG | IFF_NOTRAILERS | IFF_NOARP |
                          IFF_PROMISC | IFF_ALLMULTI | IFF_MULTICAST |
                          IFF_PORTSEL | IFF_AUTOMEDIA | IFF_DYNAMIC;
#endif

#ifdef __APPLE__

class InterfaceData;

using InteraceDataMap = std::map<std::string, std::shared_ptr<InterfaceData>>;

template <typename Type>
struct TypeDeleter final {
  using pointer = Type;

  void operator()(pointer p) {
    CFRelease(p);
  }
};

using UniqueCFStringRef =
    std::unique_ptr<CFStringRef, TypeDeleter<CFStringRef>>;

using UniqueCFArrayRef = std::unique_ptr<CFArrayRef, TypeDeleter<CFArrayRef>>;

class InterfaceData {
 public:
  // Interface name
  std::string interface_name;

  // Interface type
  std::string interface_type;

  // Localized Display name
  std::string display_name;

  // Interface descriptions
  std::string description;

  // Interface service name
  std::string service_name;

  // Interface service ID
  std::string service_id;

  // Interface config method (DHCP/INFIRM/BOOTP/Manual)
  std::string config_method;

  // DHCP router address
  std::string router_address;

  // List of DNS servers
  std::vector<std::string> dns_servers;

  // List of DNS domain names
  std::vector<std::string> dns_domains;

  // DNS server search order
  long dns_search_order;
};

// Trim leading and trailing white spaces
static inline std::string trim(std::string& str) {
  str.erase(str.find_last_not_of(' ') + 1);
  str.erase(0, str.find_first_not_of(' '));
  return str;
}

std::map<std::string, std::string> parseDescriptionString(
    std::string& description) {
  auto start_loc = description.find_first_of('{');
  auto end_loc = description.find_last_of('}');
  auto size = end_loc - start_loc - 1;
  description = description.substr(start_loc + 1, size);

  std::string delim = ", ";
  std::map<std::string, std::string> desc_map;
  size_t pos_start = 0u, pos_end = description.find(delim);

  while (pos_end != std::string::npos) {
    auto token = description.substr(pos_start, pos_end - pos_start);
    pos_start = pos_end + delim.length();
    pos_end = description.find(delim, pos_start);
    auto loc = token.find_first_of('=');
    auto first = token.substr(0, loc);
    first = trim(first);
    auto second = token.substr(loc + 1, token.size());
    second = trim(second);

    if (first == "entryID" || first == "prefs") {
      continue;
    }
    desc_map[first] = second;
  }

  return desc_map;
}

// Get entity device name
std::string getEntityDevice(std::map<std::string, std::string>& interface) {
  if (interface.find("entity_device") != interface.end()) {
    return interface["entity_device"];
  }
  return {};
}

std::string getDescription(
    std::map<std::string, std::string>& description_map) {
  std::vector<std::string> description;
  for (auto it = description_map.begin(); it != description_map.end(); it++) {
    auto key = it->first;
    if (key == "entity_device" || key == "address" || key == "name" ||
        key == "service") {
      continue;
    }

    auto value = it->second;
    description.emplace_back(key + " = " + value);
  }
  return osquery::join(description, "; ");
}

// Get IPv4 config method and router address
std::string getIPv4Info(SCNetworkServiceRef service, CFStringRef type) {
  SCNetworkProtocolRef ipv4 =
      SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeIPv4);
  if (ipv4) {
    CFDictionaryRef ipv4config = SCNetworkProtocolGetConfiguration(ipv4);
    if (ipv4config) {
      CFStringRef method = (CFStringRef)CFDictionaryGetValue(ipv4config, type);
      if (method) {
        std::string method_as_cstring = stringFromCFString(method);
        return method_as_cstring;
      }
    }
  }
  return {};
}

// Get DNS servers for the network service
std::vector<std::string> getDNS(SCNetworkServiceRef service, CFStringRef type) {
  std::vector<std::string> dns_info;
  SCNetworkProtocolRef dns =
      SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeDNS);
  if (dns) {
    CFDictionaryRef dnsconfig = SCNetworkProtocolGetConfiguration(dns);
    if (dnsconfig) {
      CFArrayRef config_item =
          (CFArrayRef)CFDictionaryGetValue(dnsconfig, type);
      CFIndex num_servers = CFArrayGetCount(config_item);
      for (CFIndex i = 0; i < num_servers; i++) {
        CFStringRef info = (CFStringRef)CFArrayGetValueAtIndex(config_item, i);
        std::string info_as_cstring = stringFromCFString(info);
        dns_info.emplace_back(info_as_cstring);
      }
    }
  }
  return dns_info;
}

// Get DNS server search order
signed long getDnsSearchOrder(SCNetworkServiceRef service) {
  SCNetworkProtocolRef dns =
      SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeDNS);
  if (dns) {
    CFDictionaryRef dnsconfig = SCNetworkProtocolGetConfiguration(dns);
    if (dnsconfig) {
      CFIndex order =
          (CFIndex)CFDictionaryGetValue(dnsconfig, kSCPropNetDNSSearchOrder);
      return order;
    }
  }
  return -1;
}

void findNetworkServices(SCPreferencesRef prefs,
                         InteraceDataMap& interface_map) {
  std::shared_ptr<InterfaceData> data = nullptr;
  if (prefs) {
    UniqueCFArrayRef all_services =
        (UniqueCFArrayRef)SCNetworkServiceCopyAll(prefs);

    CFIndex count_services = CFArrayGetCount(all_services.get());
    for (CFIndex i = 0; i < count_services; i++) {
      SCNetworkServiceRef service =
          (SCNetworkServiceRef)CFArrayGetValueAtIndex(all_services.get(), i);
      SCNetworkInterfaceRef interface = SCNetworkServiceGetInterface(service);
      CFStringRef service_description = CFCopyDescription(interface);

      std::string description_str = stringFromCFString(service_description);
      auto description_map = parseDescriptionString(description_str);
      std::string device = getEntityDevice(description_map);

      if (interface_map.find(device) != interface_map.end()) {
        data = interface_map[device];
      } else {
        data = std::make_shared<InterfaceData>();
        interface_map[device] = data;
      }

      UniqueCFStringRef service_name =
          (UniqueCFStringRef)SCNetworkServiceGetName(service);
      if (service_name) {
        data->service_name = stringFromCFString(service_name.get());
      }

      UniqueCFStringRef service_id =
          (UniqueCFStringRef)SCNetworkServiceGetServiceID(service);
      if (service_id) {
        data->service_id = stringFromCFString(service_id.get());
      }

      data->config_method = getIPv4Info(service, kSCPropNetIPv4ConfigMethod);
      data->router_address = getIPv4Info(service, kSCPropNetIPv4Router);

      data->dns_servers = getDNS(service, kSCPropNetDNSServerAddresses);
      data->dns_domains = getDNS(service, kSCPropNetDNSSearchDomains);
      data->dns_search_order = getDnsSearchOrder(service);

      data->description = getDescription(description_map);
    }
  }
}

// Get the list of network interfaces and update the interface data list
void getNetworkInterfaceData(InteraceDataMap& interfaces_map) {
  // Get the list of all network interfaces
  CFArrayRef all_interfaces = SCNetworkInterfaceCopyAll();
  if (all_interfaces) {
    CFIndex num_interfaces = CFArrayGetCount(all_interfaces);

    for (CFIndex i = 0; i < num_interfaces; i++) {
      SCNetworkInterfaceRef interface =
          (SCNetworkInterfaceRef)CFArrayGetValueAtIndex(all_interfaces, i);
      if (interface) {
        UniqueCFStringRef description =
            (UniqueCFStringRef)CFCopyDescription(interface);
        if (!description) {
          LOG(INFO) << "Failed to get description for the interface";
          continue;
        }

        std::string description_as_cstring =
            stringFromCFString(description.get());
        auto description_map = parseDescriptionString(description_as_cstring);

        UniqueCFStringRef bsd_name =
            (UniqueCFStringRef)SCNetworkInterfaceGetBSDName(interface);
        if (!bsd_name) {
          continue;
        }

        std::string interface_name = stringFromCFString(bsd_name.get());
        std::shared_ptr<InterfaceData> data = std::make_shared<InterfaceData>();
        interfaces_map[interface_name] = data;

        UniqueCFStringRef display_name =
            (UniqueCFStringRef)SCNetworkInterfaceGetLocalizedDisplayName(
                interface);
        if (display_name) {
          data->display_name = stringFromCFString(display_name.get());
        }

        UniqueCFStringRef interface_type =
            (UniqueCFStringRef)SCNetworkInterfaceGetInterfaceType(interface);
        if (interface_type) {
          data->interface_type = stringFromCFString(interface_type.get());
        }

        data->description = getDescription(description_map);
      }
    }
  }

  SCPreferencesRef prefs =
      SCPreferencesCreate(nullptr, CFSTR("com.osquery.pppoe"), nullptr);

  // Traverse through the list of network services and get the DNS and DHCP
  // info associated with the interfaces
  findNetworkServices(prefs, interfaces_map);
  CFRelease(prefs);
}

// List of interfaces and associated data
static InteraceDataMap interfaces;

void updateInterfaceData(Row& row) {
  std::string name = row["interface"];
  if (interfaces.find(name) == interfaces.end()) {
    return;
  }

  auto data = interfaces[name];
  if (data->config_method == "DHCP") {
    row["dhcp_enabled"] = INTEGER(1);
    row["dhcp_server"] = data->router_address;
  } else {
    row["dhcp_enabled"] = INTEGER(0);
  }

  row["connection_id"] = data->display_name;
  row["service"] = data->service_id;
  row["dns_domain"] = osquery::join(data->dns_domains, "; ");
  row["dns_server_search_order"] = osquery::join(data->dns_servers, "; ");
  row["description"] = data->description;
}

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

#ifdef __APPLE__
    updateInterfaceData(r);
#endif
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

#ifdef __APPLE__
  getNetworkInterfaceData(interfaces);
#endif

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
