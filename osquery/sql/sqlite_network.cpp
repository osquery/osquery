/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/network_v6.hpp>
#include <sqlite3.h>

namespace errc = boost::system::errc;
namespace ip = boost::asio::ip;

namespace osquery {

static void sqliteCidrBlockFunc(sqlite3_context* context,
                                int argc,
                                sqlite3_value** argv) {
  const size_t cidr_idx = 0, ipaddr_idx = 1;
  if (sqlite3_value_type(argv[cidr_idx]) != SQLITE_TEXT) {
    sqlite3_result_error(context, "CIDR must be a string", -1);
    return;
  }

  if (sqlite3_value_type(argv[ipaddr_idx]) != SQLITE_TEXT) {
    sqlite3_result_error(context, "IP address must be a string", -1);
    return;
  }

  const char* cidr_str =
      reinterpret_cast<const char*>(sqlite3_value_text(argv[cidr_idx]));
  const char* ipaddr_str =
      reinterpret_cast<const char*>(sqlite3_value_text(argv[ipaddr_idx]));

  boost::system::error_code ec;
  ip::address ipaddr = ip::make_address(ipaddr_str, ec);
  if (ec.value() != errc::success) {
    sqlite3_result_error(context, "IP address cannot be parsed", -1);
    return;
  }

  if (ipaddr.is_v4()) {
    ip::network_v4 network = ip::make_network_v4(cidr_str, ec);
    if (ec.value() != errc::success) {
      sqlite3_result_error(
          context, "CIDR for IP address v4 cannot be parsed", -1);
      return;
    }

    ip::address_v4_range all_network_hosts = network.hosts();
    bool is_in_range =
        all_network_hosts.find(ipaddr.to_v4()) != all_network_hosts.end();
    sqlite3_result_int(context, is_in_range);
  } else if (ipaddr.is_v6()) {
    ip::network_v6 network = ip::make_network_v6(cidr_str, ec);
    if (ec.value() != errc::success) {
      sqlite3_result_error(
          context, "CIDR for IP address v6 cannot be parsed", -1);
      return;
    }

    ip::address_v6_range all_network_hosts = network.hosts();
    bool is_in_range =
        all_network_hosts.find(ipaddr.to_v6()) != all_network_hosts.end();
    sqlite3_result_int(context, is_in_range);
  }
}

void registerNetworkExtensions(sqlite3* db) {
  sqlite3_create_function(db,
                          "in_cidr_block",
                          2,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          sqliteCidrBlockFunc,
                          nullptr,
                          nullptr);
}
} // namespace osquery
