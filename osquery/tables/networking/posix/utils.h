/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
