// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_TABLES_NETWORKING_H
#define OSQUERY_TABLES_NETWORKING_H

#include <string>

#include <ifaddrs.h>
#include <arpa/inet.h>

// Return a string representation for an IPv4/IPv6 struct.
std::string canonical_ip_address(const struct sockaddr*);
std::string canonical_mac_address(const struct ifaddrs *addr);

#endif /* OSQUERY_TABLES_NETWORKING_H */
