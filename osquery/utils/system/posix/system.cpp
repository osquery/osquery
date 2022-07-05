/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "system.h"

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <osquery/utils/system/system.h>

#include <boost/algorithm/string.hpp>

namespace osquery {
std::string getHostname() {
  /* POSIX states that the maximum amount of bytes for a hostname is 255 bytes
     though gethostname includes the null terminator too in the size. */
  std::size_t max_size = 256;

  std::vector<char> hostname(max_size, 0);
  gethostname(hostname.data(), max_size);

  std::string hostname_string(hostname.data());
  boost::algorithm::trim(hostname_string);
  return hostname_string;
}

std::string getFqdn() {
  std::string fqdn_string = getHostname();

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_CANONNAME;

  struct addrinfo* res = nullptr;
  if (getaddrinfo(fqdn_string.c_str(), nullptr, &hints, &res) == 0) {
    if (res->ai_canonname != nullptr) {
      fqdn_string = res->ai_canonname;
    }
  }
  if (res != nullptr) {
    freeaddrinfo(res);
  }

  return fqdn_string;
}
} // namespace osquery
