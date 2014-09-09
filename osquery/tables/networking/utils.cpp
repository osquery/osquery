// Copyright 2004-present Facebook. All Rights Reserved.

#include <iomanip>
#include <sstream>

#include <net/if_dl.h>

#include <boost/algorithm/string/trim.hpp>

#include "osquery/tables/networking/utils.h"

std::string canonical_ip_address(const struct sockaddr *in) {
  char dst[INET6_ADDRSTRLEN];
  memset(dst, 0, sizeof(dst));
  void *in_addr;

  if (in->sa_family == AF_INET) {
    in_addr = (void *)&(((struct sockaddr_in *)in)->sin_addr);
  } else if (in->sa_family == AF_INET6) {
    in_addr = (void *)&(((struct sockaddr_in6 *)in)->sin6_addr);
  } else {
    return "";
  }

  inet_ntop(in->sa_family, in_addr, dst, sizeof(dst));
  std::string address(dst);
  boost::trim(address);

  return address;
}

std::string canonical_mac_address(const struct ifaddrs *addr) {
  std::stringstream mac;
  struct sockaddr_dl *sdl;

  if (addr->ifa_addr == NULL) {
    // No link or MAC exists.
    return "";
  }

  sdl = (struct sockaddr_dl *)addr->ifa_addr;
  if (sdl->sdl_alen != 6) {
    // Do not support MAC address that are not 6 bytes...
    return "";
  }

  for (size_t i = 0; i < sdl->sdl_alen; i++) {
    mac << std::hex << std::setfill('0') << std::setw(2);
    // Prevent char sign extension.
    mac << (int)((uint8_t)sdl->sdl_data[i + sdl->sdl_nlen]) << ":";
  }
  return mac.str();
}
