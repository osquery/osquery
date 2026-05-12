/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 *
 * FreeBSD ARP cache: walks the routing table via PF_ROUTE / NET_RT_FLAGS,
 * mirroring the legacy approach used by arp(8) in base.  FreeBSD also has a
 * netlink-based API for the same data, but that requires the netlink kernel
 * module (only autoloaded on 14+ GENERIC) — the routing-socket path works on
 * every FreeBSD release the port supports, with no kld dependency.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>

#ifndef SA_SIZE
#define SA_SIZE(sa)                                                            \
  ((!(sa) || ((struct sockaddr*)(sa))->sa_len == 0)                            \
       ? sizeof(long)                                                          \
       : 1 + ((((struct sockaddr*)(sa))->sa_len - 1) | (sizeof(long) - 1)))
#endif

namespace osquery {
namespace tables {

QueryData genArpCache(QueryContext& context) {
  QueryData results;

  int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO};
  size_t needed = 0;
  if (sysctl(mib, 6, nullptr, &needed, nullptr, 0) < 0 || needed == 0) {
    return results;
  }

  std::vector<char> buf;
  for (;;) {
    buf.resize(needed);
    int st = sysctl(mib, 6, buf.data(), &needed, nullptr, 0);
    if (st == 0) {
      break;
    }
    if (errno != ENOMEM) {
      return results;
    }
    needed += needed / 8;
  }

  char ifname[IF_NAMESIZE];
  char* lim = buf.data() + needed;
  for (char* next = buf.data(); next < lim;) {
    auto* rtm = reinterpret_cast<struct rt_msghdr*>(next);
    if (rtm->rtm_msglen == 0) {
      break;
    }
    auto* sin2 = reinterpret_cast<struct sockaddr_in*>(rtm + 1);
    auto* sdl = reinterpret_cast<struct sockaddr_dl*>(
        reinterpret_cast<char*>(sin2) + SA_SIZE(sin2));

    char addrbuf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &sin2->sin_addr, addrbuf, sizeof(addrbuf));

    // Format MAC from sockaddr_dl.
    std::string mac;
    if (sdl->sdl_alen == 6) {
      char macbuf[32];
      const unsigned char* m =
          reinterpret_cast<const unsigned char*>(LLADDR(sdl));
      snprintf(macbuf,
               sizeof(macbuf),
               "%02x:%02x:%02x:%02x:%02x:%02x",
               m[0],
               m[1],
               m[2],
               m[3],
               m[4],
               m[5]);
      mac = macbuf;
    }

    std::string interface;
    if (if_indextoname(sdl->sdl_index, ifname) != nullptr) {
      interface = ifname;
    }

    Row r;
    r["address"] = addrbuf;
    r["mac"] = mac;
    r["interface"] = interface;
    r["permanent"] = (rtm->rtm_rmx.rmx_expire == 0) ? "1" : "0";
    results.push_back(r);

    next += rtm->rtm_msglen;
  }
  return results;
}

} // namespace tables
} // namespace osquery
