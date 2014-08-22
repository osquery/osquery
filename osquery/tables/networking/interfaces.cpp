// Copyright 2004-present Facebook. All Rights Reserved.

#include <sstream>
#include <iomanip>

#include <ifaddrs.h>
#include <net/if.h>

#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "utils.h"

using namespace osquery::core;
using namespace osquery::db;

namespace osquery {
namespace tables {

// Macros for safe sign-extension
#define STRING_FROM_UCHAR(x) boost::lexical_cast<std::string>((uint16_t)x);
#define STRING_FROM_UINT32(x) boost::lexical_cast<std::string>((uint64_t)x);

void genAddressesFromAddr(const struct ifaddrs *addr, QueryData &results) {
  std::string dest_address;
  Row r;
  r["interface"] = std::string(addr->ifa_name);

  // Address and mask will appear everytime.
  r["address"] = canonical_ip_address((struct sockaddr *)addr->ifa_addr);
  r["mask"] = canonical_ip_address((struct sockaddr *)addr->ifa_netmask);

  // The destination address is used for either a broadcast or PtP address.
  if (addr->ifa_dstaddr != NULL) {
    dest_address = canonical_ip_address((struct sockaddr *)addr->ifa_dstaddr);
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
  r["mac"] = canonical_mac_address(addr);

  ifd = (struct if_data *)addr->ifa_data;
  r["type"] = STRING_FROM_UCHAR(ifd->ifi_type);
  r["mtu"] = STRING_FROM_UINT32(ifd->ifi_mtu);
  r["metric"] = STRING_FROM_UINT32(ifd->ifi_metric);
  r["ipackets"] = STRING_FROM_UINT32(ifd->ifi_ipackets);
  r["opackets"] = STRING_FROM_UINT32(ifd->ifi_opackets);
  r["ibytes"] = STRING_FROM_UINT32(ifd->ifi_ibytes);
  r["obytes"] = STRING_FROM_UINT32(ifd->ifi_obytes);
  r["ierrors"] = STRING_FROM_UINT32(ifd->ifi_ierrors);
  r["oerrors"] = STRING_FROM_UINT32(ifd->ifi_oerrors);
  r["last_change"] = STRING_FROM_UINT32(ifd->ifi_lastchange.tv_sec);
  results.push_back(r);
}

QueryData genInterfaceAddresses() {
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

QueryData genInterfaceDetails() {
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
