/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>

#include <ifaddrs.h>
#include <arpa/inet.h>

namespace osquery {
namespace tables {

// Define AF_INTERFACE as the alias for interface details.
#ifdef __APPLE__
#define AF_INTERFACE AF_LINK
#else
#define AF_INTERFACE AF_PACKET
#endif

// Return a string representation for an IPv4/IPv6 struct.
std::string ipAsString(const struct sockaddr *in);
std::string macAsString(const struct ifaddrs *addr);
std::string macAsString(const char *addr);
int netmaskFromIP(const struct sockaddr *in);
}
}
