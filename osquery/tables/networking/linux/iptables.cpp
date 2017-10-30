/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <libiptc/libiptc.h>

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/networking/utils.h"

namespace osquery {
namespace tables {

static const std::string kLinuxIpTablesNames = "/proc/net/ip_tables_names";
static const std::string kHexMap = "0123456789ABCDEF";

static const int kMaskHighBits = 4;
static const int kMaskLowBits = 15;

void parseIpEntry(const ipt_ip *ip, Row &r) {
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

  r["src_ip"] = ipAsString(&ip->src);
  r["dst_ip"] = ipAsString(&ip->dst);
  r["src_mask"] = ipAsString(&ip->smsk);
  r["dst_mask"] = ipAsString(&ip->dmsk);

  char aux_char[2] = {0};
  std::string iniface_mask;
  for (int i = 0; i < IFNAMSIZ && ip->iniface_mask[i] != 0x00; i++) {
    aux_char[0] = kHexMap[(int)ip->iniface_mask[i] >> kMaskHighBits];
    aux_char[1] = kHexMap[(int)ip->iniface_mask[i] & kMaskLowBits];
    iniface_mask += aux_char[0];
    iniface_mask += aux_char[1];
  }

  r["iniface_mask"] = TEXT(iniface_mask);
  std::string outiface_mask = "";
  for (int i = 0; i < IFNAMSIZ && ip->outiface_mask[i] != 0x00; i++) {
    aux_char[0] = kHexMap[(int)ip->outiface_mask[i] >> kMaskHighBits];
    aux_char[1] = kHexMap[(int)ip->outiface_mask[i] & kMaskLowBits];
    outiface_mask += aux_char[0];
    outiface_mask += aux_char[1];
  }
  r["outiface_mask"] = TEXT(outiface_mask);
}

void parseEntryMatch(const struct ipt_entry* en, Row& r) {
  // Get rule port details from the xt_entry_match object

  auto m = (struct xt_entry_match*)en->elems;

  if (en->ip.proto == IPPROTO_TCP) {
    auto m_data = (struct ipt_tcp*)m->data;
    r["src_port"] = (m_data)
                        ? std::to_string(m_data->spts[0]) + ":" +
                              std::to_string(m_data->spts[1])
                        : "-1";
    r["dst_port"] = (m_data)
                        ? std::to_string(m_data->dpts[0]) + ":" +
                              std::to_string(m_data->dpts[1])
                        : "-1";

  } else if (en->ip.proto == IPPROTO_UDP) {
    auto m_data = (struct ipt_udp*)m->data;
    r["src_port"] = (m_data)
                        ? std::to_string(m_data->spts[0]) + ":" +
                              std::to_string(m_data->spts[1])
                        : "-1";
    r["dst_port"] = (m_data)
                        ? std::to_string(m_data->dpts[0]) + ":" +
                              std::to_string(m_data->dpts[1])
                        : "-1";

  } else {
    r["src_port"] = "0";
    r["dst_port"] = "0";
  }
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

    const struct ipt_entry *prev_rule = nullptr;
    // Iterating through all the rules per chain
    for (const struct ipt_entry *chain_rule = iptc_first_rule(chain, handle);
         chain_rule;
         chain_rule = iptc_next_rule(prev_rule, handle)) {
      prev_rule = chain_rule;

      auto target = iptc_get_target(chain_rule, handle);
      if (target != nullptr) {
        r["target"] = TEXT(target);
      } else {
        r["target"] = "";
      }

      if (chain_rule->target_offset) {
        r["match"] = "yes";
        // fill protocol port details
        parseEntryMatch(chain_rule, r);
      } else {
        r["match"] = "no";
        r["src_port"] = "";
        r["dst_port"] = "";
      }

      const struct ipt_ip *ip = &chain_rule->ip;
      parseIpEntry(ip, r);

      results.push_back(r);
    } // Rule iteration
    results.push_back(r);
  } // Chain iteration

  iptc_free(handle);
}

QueryData genIptables(QueryContext &context) {
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
