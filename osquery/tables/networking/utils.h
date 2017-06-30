/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <map>
#include <string>

#include <ifaddrs.h>
#include <arpa/inet.h>

#include <osquery/database.h>

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

// Linux proc protocol define to net stats file name.
extern const std::map<int, std::string> kLinuxProtocolNames;
// A map of socket handles (inodes) to their pid and file descriptor.
typedef std::map<std::string, std::pair<std::string, std::string>> InodeMap;
std::string addressFromHex(const std::string& encoded_address, int family);
unsigned short portFromHex(const std::string& encoded_port);
void genSocketsFromProc(const InodeMap& inodes,
                        int protocol,
                        int family,
                        QueryData& results);
}
}
