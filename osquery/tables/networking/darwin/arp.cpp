// Copyright 2004-present Facebook. All Rights Reserved.

#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>

#include "osquery/database.h"

namespace osquery {
namespace tables {

typedef struct {
  struct rt_msghdr m_rtm;
  char m_space[512];
} route_msg;

// Transform the ethernet address in a string
std::string ether_print(u_char *cp) {
  const char etherAddressSize = 18;
  char buf[etherAddressSize];

  snprintf(buf,
	   etherAddressSize,
	   "%02x:%02x:%02x:%02x:%02x:%02x",
	   cp[0],
	   cp[1],
	   cp[2],
	   cp[3],
	   cp[4],
	   cp[5]);

  return std::string(buf);
}

void add_address(struct rt_msghdr *rtm, QueryData *results) {
  Row r;
  char *ip_addr;
  std::string mac_addr;
  struct hostent *hp;
  struct sockaddr_inarp *sin;
  struct sockaddr_dl *sdl;

  sin = (struct sockaddr_inarp *)(rtm + 1);
  sdl = (struct sockaddr_dl *)(sin + 1);

  ip_addr = inet_ntoa(sin->sin_addr);

  if (sdl->sdl_alen != 0) {
    mac_addr = ether_print((u_char *)LLADDR(sdl));
  } else {
    mac_addr = "incomplete";
  }
  if (rtm->rtm_rmx.rmx_expire == 0) {
    mac_addr = "permanent";
  }
  if (rtm->rtm_addrs & RTA_NETMASK) {
    sin = (struct sockaddr_inarp *)(sdl->sdl_len + (char *)sdl);

    if (sin->sin_addr.s_addr == 0xffffffff)
      mac_addr = "published";

    if (sin->sin_len != 8)
      mac_addr = "weird";
  }

  r["ip"] = ip_addr;
  r["mac"] = mac_addr;

  results->push_back(r);
}

QueryData genArp() {
  QueryData results;

  int mib[6];
  size_t needed;
  char *lim, *buf, *next;
  struct rt_msghdr *rtm;
  int found_entry = 0;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_INET;
  mib[4] = NET_RT_FLAGS;
  mib[5] = RTF_LLINFO;

  sysctl(mib, 6, nullptr, &needed, nullptr, 0);
  buf = (char *)malloc(needed);

  if (sysctl(mib, 6, buf, &needed, nullptr, 0) < 0) {
    free(buf);

    return results;
  }

  lim = buf + needed;
  for (next = buf; next < lim; next += rtm->rtm_msglen) {
    rtm = (struct rt_msghdr *)(void *) next;
    add_address(rtm, &results);
  }
  free(buf);
  
  return results;
}
}
}
