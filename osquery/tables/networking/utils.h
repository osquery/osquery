/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <string>

#include <ifaddrs.h>
#include <arpa/inet.h>

namespace osquery {
namespace tables {

// Define AF_INTERFACE as the alias for interface details.
#ifdef __linux__
#define AF_INTERFACE AF_PACKET
#else
#define AF_INTERFACE AF_LINK
#endif

// Return a string representation for an IPv4/IPv6 struct.
std::string ipAsString(const struct sockaddr *in);
std::string ipAsString(const struct in_addr *in);
std::string macAsString(const struct ifaddrs *addr);
std::string macAsString(const char *addr);
int netmaskFromIP(const struct sockaddr *in);
}
}
