// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <string>

#include <ifaddrs.h>
#include <arpa/inet.h>

namespace osquery {
namespace tables {

// Return a string representation for an IPv4/IPv6 struct.
std::string ipAsString(const struct sockaddr *in);
std::string macAsString(const struct ifaddrs *addr);
std::string macAsString(const char *addr);
int netmaskFromIP(const struct sockaddr *in);
}
}
