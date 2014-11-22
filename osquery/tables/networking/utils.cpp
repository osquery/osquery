// Copyright 2004-present Facebook. All Rights Reserved.

#include <iomanip>
#include <sstream>

#if defined(__linux__)
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#define AF_LINK AF_PACKET
#elif defined(__FreeBSD__)
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if_dl.h>
#else
#include <net/if_dl.h>
#endif

#include <boost/algorithm/string/trim.hpp>

#include "osquery/tables/networking/utils.h"

namespace osquery {
namespace tables {

std::string ipAsString(const struct sockaddr *in) {
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

int netmaskFromIP(const struct sockaddr *in) {
  int mask = 0;

  if (in->sa_family == AF_INET6) {
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)in;
    for (size_t i = 0; i < 16; i++) {
      mask += addBits(in6->sin6_addr.s6_addr[i]);
    }
  } else {
    struct sockaddr_in *in4 = (struct sockaddr_in *)in;
    char *address = reinterpret_cast<char *>(&in4->sin_addr.s_addr);
    for (size_t i = 0; i < 4; i++) {
      mask += addBits(address[i]);
    }
  }

  return mask;
}

std::string macAsString(const char *addr) {
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

std::string macAsString(const struct ifaddrs *addr) {
  std::stringstream mac;

  if (addr->ifa_addr == NULL) {
    // No link or MAC exists.
    return "";
  }

#if defined(__linux__)
  struct ifreq ifr;

  int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strcpy(ifr.ifr_name, addr->ifa_name);
  ioctl(socket_fd, SIOCGIFHWADDR, &ifr);
  close(socket_fd);

  for (size_t i = 0; i < 6; i++) {
    mac << std::hex << std::setfill('0') << std::setw(2);
    mac << (int)((uint8_t)ifr.ifr_hwaddr.sa_data[i]);
    if (i != 5) {
      mac << ":";
    }
  }
#else
  struct sockaddr_dl *sdl;

  sdl = (struct sockaddr_dl *)addr->ifa_addr;
  if (sdl->sdl_alen != 6) {
    // Do not support MAC address that are not 6 bytes...
    return "";
  }

  for (size_t i = 0; i < sdl->sdl_alen; i++) {
    mac << std::hex << std::setfill('0') << std::setw(2);
    // Prevent char sign extension.
    mac << (int)((uint8_t)sdl->sdl_data[i + sdl->sdl_nlen]);
    if (i != 5) {
      mac << ":";
    }
  }
#endif

  return mac.str();
}
}
}
