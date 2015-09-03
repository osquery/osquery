/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#include <arpa/inet.h>
#include <libiptc/libiptc.h>

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/networking/utils.h"

namespace osquery {
namespace tables {

const std::string kLinuxIpTablesNames = "/proc/net/ip_tables_names";
const char MAP[] = {'0','1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
const int HIGH_BITS = 4;
const int LOW_BITS = 15;

void parseIpEntry(ipt_ip *ip, Row &r) {
  r["protocol"] = INTEGER(ip->proto);
  if (strlen(ip->iniface)) {
    r["iniface"] = TEXT(ip->iniface);
  } else {
    r["iniface"] = "all";
  }

  if (strlen(ip->outiface)) {
    r["outiface"] = TEXT(ip->outiface);
  } else {
   r["outiface"] = "all";
  }

  r["src_ip"] = ipAsString((struct in_addr *)&ip->src);
  r["dst_ip"] = ipAsString((struct in_addr *)&ip->dst);
  r["src_mask"] = ipAsString((struct in_addr *)&ip->smsk);
  r["dst_mask"] = ipAsString((struct in_addr *)&ip->dmsk);

  char aux_char[2] = {0};
  std::string iniface_mask;
  for (int i = 0; i < IFNAMSIZ && ip->iniface_mask[i] != 0x00; i++) {
    aux_char[0] = MAP[(int) ip->iniface_mask[i] >> HIGH_BITS];
    aux_char[1] = MAP[(int) ip->iniface_mask[i] & LOW_BITS];
    iniface_mask += aux_char[0];
    iniface_mask += aux_char[1];
  }

  r["iniface_mask"] = TEXT(iniface_mask);
  std::string outiface_mask = "";
  for (int i = 0; i < IFNAMSIZ && ip->outiface_mask[i] != 0x00; i++) {
    aux_char[0] = MAP[(int) ip->outiface_mask[i] >> HIGH_BITS];
    aux_char[1] = MAP[(int) ip->outiface_mask[i] & LOW_BITS];
    outiface_mask += aux_char[0];
    outiface_mask += aux_char[1];
  }
  r["outiface_mask"] = TEXT(outiface_mask);
}

void genIPTablesRules(const std::string &filter, QueryData &results) {
  Row r;
  r["filter_name"] = filter;

  // Initialize the access to iptc
  auto handle = (struct iptc_handle *)iptc_init(filter.c_str());
  if (handle == nullptr) {
    return;
  }

  // Iterate through chains
  for (auto chain = iptc_first_chain(handle); chain != nullptr;
       chain = iptc_next_chain(handle)) {
    r["chain"] = TEXT(chain);

    struct ipt_counters counters;
    auto policy = iptc_get_policy(chain, &counters, handle);

    if (policy != nullptr) {
      r["policy"] = TEXT(policy);
      r["packets"] = INTEGER(counters.pcnt);
      r["bytes"] = INTEGER(counters.bcnt);
    } else {
      r["policy"] = "";
      r["packets"] = "0";
      r["bytes"] = "0";
    }

    struct ipt_entry *prev_rule = nullptr;
    // Iterating through all the rules per chain
    for (auto chain_rule = iptc_first_rule(chain, handle); chain_rule;
         chain_rule = iptc_next_rule(prev_rule, handle)) {
      prev_rule = (struct ipt_entry *)chain_rule;

      auto target = iptc_get_target(chain_rule, handle);
      if (target != nullptr) {
        r["target"] = TEXT(target);
      } else {
        r["target"] = "";
      }

      if (chain_rule->target_offset) {
        r["match"] = "yes";
      } else {
        r["match"] = "no";
      }

      struct ipt_ip *ip = (struct ipt_ip *)&chain_rule->ip;
      parseIpEntry(ip, r);

      results.push_back(r);
    } // Rule iteration
    results.push_back(r);
  } // Chain iteration

  iptc_free(handle);
}

QueryData genIptables(QueryContext& context) {
  QueryData results;

  // Read in table names
  std::string content;
  auto s = osquery::readFile(kLinuxIpTablesNames, content);
  if (s.ok()) {
    for (auto &line : split(content, "\n")) {
      boost::trim(line);
      if (line.size() > 0) {
        genIPTablesRules(line, results);
      }
    }
  } else {
    // Permissions issue or iptables modules are not loaded.
    TLOG << "Error reading " << kLinuxIpTablesNames << " : " << s.toString();
  }

  return results;
}
}
}
