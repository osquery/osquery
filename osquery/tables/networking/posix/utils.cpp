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

#if defined(__linux__) || defined(__FreeBSD__)
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <net/if_dl.h>
#endif

#if defined(__linux__)
#define AF_LINK AF_PACKET
#endif

#include <boost/algorithm/string/trim.hpp>

#include "osquery/tables/networking/utils.h"

namespace osquery {
namespace tables {

std::string ipAsString(const struct sockaddr* in) {
  char dst[INET6_ADDRSTRLEN] = {0};
  void* in_addr = nullptr;

  if (in->sa_family == AF_INET) {
    in_addr = (void*)&(((struct sockaddr_in*)in)->sin_addr);
  } else if (in->sa_family == AF_INET6) {
    in_addr = (void*)&(((struct sockaddr_in6*)in)->sin6_addr);
  } else {
    return "";
  }

  inet_ntop(in->sa_family, in_addr, dst, sizeof(dst));
  std::string address(dst);
  boost::trim(address);
  return address;
}

std::string ipAsString(const struct in_addr* in) {
  char dst[INET6_ADDRSTRLEN] = {0};

  inet_ntop(AF_INET, in, dst, sizeof(dst));
  std::string address(dst);
  boost::trim(address);
  return address;
}

inline short addBits(unsigned char byte) {
  short bits = 0;
  for (int i = 7; i >= 0; --i) {
    if ((byte & (1 << i)) == 0) {
      break;
    }
    bits++;
  }
  return bits;
}

int netmaskFromIP(const struct sockaddr* in) {
  int mask {0};

  if (in->sa_family == AF_INET6) {
    auto in6 = (struct sockaddr_in6*)in;
    for (size_t i = 0; i < 16; i++) {
      mask += addBits(in6->sin6_addr.s6_addr[i]);
    }
  } else {
    auto in4 = (struct sockaddr_in*)in;
    auto address = reinterpret_cast<char*>(&in4->sin_addr.s_addr);
    for (size_t i = 0; i < 4; i++) {
      mask += addBits(address[i]);
    }
  }

  return mask;
}

inline std::string macAsString(const char* addr) {
  std::stringstream mac;

  for (size_t i = 0; i < 6; i++) {
    mac << std::hex << std::setfill('0') << std::setw(2);
    mac << (int)((uint8_t)addr[i]);
    if (i != 5) {
      mac << ":";
    }
  }

  return mac.str();
}

std::string macAsString(const struct ifaddrs* addr) {
  static std::string blank_mac = "00:00:00:00:00:00";
  if (addr->ifa_addr == nullptr) {
    // No link or MAC exists.
    return blank_mac;
  }

#if defined(__linux__)
  if (addr->ifa_name == nullptr) {
    return blank_mac;
  }

  struct ifreq ifr;
  ifr.ifr_addr.sa_family = AF_INET;
  memcpy(ifr.ifr_name, addr->ifa_name, IFNAMSIZ);

  int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_fd < 0) {
    return blank_mac;
  }
  ioctl(socket_fd, SIOCGIFHWADDR, &ifr);
  close(socket_fd);

  return macAsString(ifr.ifr_hwaddr.sa_data);
#else
  auto sdl = (struct sockaddr_dl*)addr->ifa_addr;
  if (sdl->sdl_alen != 6) {
    // Do not support MAC address that are not 6 bytes...
    return blank_mac;
  }

  return macAsString(&sdl->sdl_data[sdl->sdl_nlen]);
#endif
}
}
}
