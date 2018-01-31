/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <netinet/in.h>

#include <resolv.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/networking/utils.h"

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_dns_resolvers_defs.hpp>


namespace osquery {
namespace tables {

QueryData genDNSResolvers(QueryContext& context) {
  QueryData results;

  // libresolv will populate a global structure with resolver information.
  if (res_init() == -1) {
    return {};
  }

  // The global structure is called "_res" and is of the semi-opaque type
  // struct __res_state from the same resolv.h. An application many communicate
  // with the resolver discovery, but we are interested in the default state.
  struct __res_state& rr = _res;
  if (rr.nscount > 0) {
    for (size_t i = 0; i < static_cast<size_t>(_res.nscount); i++) {
      Row r;
      r["id"] = INTEGER(i);
      r["type"] = "nameserver";
      r["address"] = ipAsString((const struct sockaddr*)&_res.nsaddr_list[i]);
      r["netmask"] = "32";
      // Options applies to every resolver.
      r["options"] = BIGINT(_res.options);
      results.push_back(r);
    }
  }

  if (_res.nsort > 0) {
    for (size_t i = 0; i < static_cast<size_t>(_res.nsort); i++) {
      Row r;
      r["id"] = INTEGER(i);
      r["type"] = "sortlist";
      r["address"] =
          ipAsString((const struct sockaddr*)&_res.sort_list[i].addr);
      r["netmask"] = INTEGER(_res.sort_list[i].mask);
      r["options"] = BIGINT(_res.options);
      results.push_back(r);
    }
  }

  for (size_t i = 0; i < MAXDNSRCH; i++) {
    if (_res.dnsrch[i] != nullptr) {
      Row r;
      r["id"] = INTEGER(i);
      r["type"] = "search";
      r["address"] = std::string(_res.dnsrch[0]);
      r["options"] = BIGINT(_res.options);
      results.push_back(r);
    }
  }

  res_close();
  return results;
}
}
}
