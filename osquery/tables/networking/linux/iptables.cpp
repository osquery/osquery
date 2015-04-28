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


#include <osquery/tables.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace osquery {
namespace tables {

const std::string kLinuxIpTablesNames = "/proc/net/ip_tables_names";
const char MAP[] = {'0','1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
const int HIGH_BITS = 4;
const int LOW_BITS = 15;

QueryData getIptablesRules(const std::string& content) {
  QueryData results;

  for (auto& line : split(content, "\n")) {
    if (line.size() == 0) {
      continue;
    }

    // Inline trim each line.
    boost::trim(line);

    Row r;

    r["filter_name"] = TEXT(line);

    struct iptc_handle *h;

    // Initialize the access to iptc
    h = (struct iptc_handle*) iptc_init(line.c_str());

    if (h) {
      // Iterate through chains
      for (auto chain = iptc_first_chain((struct iptc_handle*)h); chain; chain = iptc_next_chain((struct iptc_handle*)h))  {
        r["chain"] = TEXT(chain);

        struct ipt_counters counters;
        const char* policy;

        if ((policy = iptc_get_policy(chain, &counters, (struct iptc_handle*)h))) {
          r["policy"] = TEXT(policy);
          r["packets"] = INTEGER(counters.pcnt);
          r["bytes"] = INTEGER(counters.bcnt);
        }

        struct ipt_entry *prev_rule;

        // Iterating through all the rules per chain
        for (auto chain_rule = iptc_first_rule(chain, (struct iptc_handle*)h); chain_rule; chain_rule = iptc_next_rule(prev_rule, (struct iptc_handle*)h))  {
          prev_rule = (struct ipt_entry*)chain_rule;
          struct ipt_ip *ip = (struct ipt_ip*)&chain_rule->ip;
          auto target = iptc_get_target(chain_rule, (struct iptc_handle*)h);
          if (target) {
            r["target"] = TEXT(target);
          }
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
          char src_ip_string[INET6_ADDRSTRLEN] = {0};
          if (inet_ntop(AF_INET, (struct in_addr *)&ip->src, src_ip_string, INET6_ADDRSTRLEN) != NULL) {
            r["src_ip"] = TEXT(src_ip_string);
          }
          char dst_ip_string[INET6_ADDRSTRLEN] = {0};
          if (inet_ntop(AF_INET, (struct in_addr *)&ip->dst, dst_ip_string, INET6_ADDRSTRLEN) != NULL) {
            r["dst_ip"] = TEXT(dst_ip_string);
          }
          char src_ip_mask[INET6_ADDRSTRLEN] = {0};
          if (inet_ntop(AF_INET, (struct in_addr *)&ip->smsk, src_ip_mask, INET6_ADDRSTRLEN) != NULL) {
            r["src_mask"] = TEXT(src_ip_mask);
          }
          char dst_ip_mask[INET6_ADDRSTRLEN] = {0};
          if (inet_ntop(AF_INET, (struct in_addr *)&ip->dmsk, dst_ip_mask, INET6_ADDRSTRLEN) != NULL) {
            r["dst_mask"] = TEXT(dst_ip_mask);
          }

          char aux_char[2];
          std::string iniface_mask = "";
          for (int i = 0; ip->iniface_mask[i] != 0x00 && i<IFNAMSIZ; i++) {
            aux_char[0] = MAP[(int) ip->iniface_mask[i] >> HIGH_BITS];
            aux_char[1] = MAP[(int) ip->iniface_mask[i] & LOW_BITS];
            iniface_mask += aux_char[0];
            iniface_mask += aux_char[1];
          }

          r["iniface_mask"] = TEXT(iniface_mask);
          std::string outiface_mask = "";
          for (int i = 0; ip->outiface_mask[i] != 0x00 && i<IFNAMSIZ; i++) {
            aux_char[0] = MAP[(int) ip->outiface_mask[i] >> HIGH_BITS];
            aux_char[1] = MAP[(int) ip->outiface_mask[i] & LOW_BITS];
            outiface_mask += aux_char[0];
            outiface_mask += aux_char[1];
          }
          r["outiface_mask"] = TEXT(outiface_mask);

          if (chain_rule->target_offset) {
            r["match"] = "yes";
          } else {
            r["match"] = "no";
          }
          results.push_back(r);
        } // Rule iteration
        results.push_back(r);
      } // Chain iteration

      iptc_free((struct iptc_handle*) h);

    }
  } // Filter table iteration

  return results;
}

QueryData genIptables(QueryContext& context) {
  std::string content;
  QueryData results;

  auto s = osquery::readFile(kLinuxIpTablesNames, content);

  if (s.ok()) {
    return getIptablesRules(content);
  } else {
    LOG(ERROR) << "Error reading " << kLinuxIpTablesNames << " : " << s.toString();
    return {};
  }
}
}
}
