/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <arpa/inet.h>
#include <netdb.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genLookup(QueryContext& context) {
  QueryData results;

  if (context.constraints.count("address") > 0 &&
      context.constraints.at("address").exists(EQUALS)) {
    for (const auto& ip_str : context.constraints.at("address").getAll(EQUALS)) {
      struct sockaddr_in ip4addr;
      struct sockaddr_in6 ip6addr;
      const struct sockaddr* addr =
        reinterpret_cast<const struct sockaddr *>(&ip4addr);

#ifdef __MAC__
      ip4addr.sin_len = sizeof(ip4addr);
#else
      size_t len = sizeof(ip4addr);
#endif
      ip4addr.sin_family = AF_INET;
      ip4addr.sin_port = 0;
      auto result = inet_pton(AF_INET, ip_str.c_str(), &ip4addr.sin_addr);
      if (result != 1) {
#ifdef __MAC__
        ip6addr.sin6_len = sizeof(ip6addr);
#else
        len = sizeof(ip6addr);
#endif
        ip6addr.sin6_family = AF_INET6;
        ip6addr.sin6_port = 0;
        ip6addr.sin6_flowinfo = 0;
        ip6addr.sin6_scope_id = 0;
        addr = reinterpret_cast<const struct sockaddr *>(&ip6addr);
        result = inet_pton(AF_INET6, ip_str.c_str(), &ip6addr.sin6_addr);
      }
      if (result != 1) {
        continue;
      }

      char hostname[NI_MAXHOST];
      if (getnameinfo(
        addr,
#ifdef __MAC__
        addr->sa_len,
#else
        len,
#endif
        hostname,
        sizeof(hostname),
        nullptr,
        0,
        NI_NAMEREQD) != 0) {
        continue;
      }

      Row r;
      r["address"] = ip_str;
      r["hostname"] = hostname;
      results.push_back(r);
    }
  }

  if (context.constraints.count("hostname") > 0 &&
      context.constraints.at("hostname").exists(EQUALS)) {
    struct addrinfo hints;
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = 0;
    hints.ai_protocol = IPPROTO_UDP;  // If you don't specify one, you'll get a row for each
    hints.ai_flags = AI_ADDRCONFIG;

    for (const auto& hostname : context.constraints.at("hostname").getAll(EQUALS)) {
      struct addrinfo* addr0;
      if (getaddrinfo(
        hostname.c_str(),
        nullptr,
        &hints,
        &addr0) != 0) {
          continue;
      }

      struct addrinfo* addr = addr0;
      while (addr != nullptr) {
        char ip_address_str[INET6_ADDRSTRLEN];
        struct sockaddr_in* sockaddr =
          reinterpret_cast<struct sockaddr_in *>(addr->ai_addr);
        if (inet_ntop(
          sockaddr->sin_family,
          &sockaddr->sin_addr,
          ip_address_str,
          sizeof(ip_address_str)) == nullptr) {
            continue;
        }

        Row new_row;
        new_row["hostname"] = hostname;
        new_row["address"] = ip_address_str;
        results.push_back(new_row);
        addr = addr->ai_next;
      }
      freeaddrinfo(addr0);
    }
  }
  return results;
}

}
}
