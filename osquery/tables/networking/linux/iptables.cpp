/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/networking/posix/utils.h>
#include <osquery/utils/conversions/split.h>

extern "C" {
#include <osquery/tables/networking/linux/iptc_proxy.h>
}

namespace osquery {
namespace tables {

static const std::string kLinuxIpTablesNames = "/proc/net/ip_tables_names";
static const std::string kHexMap = "0123456789ABCDEF";

static const int kMaskHighBits = 4;
static const int kMaskLowBits = 15;

namespace {
std::string formatInvFlag(const iptcproxy_rule& rule, int flag) {
  return (rule.ip_data.invflags & flag) ? "!" : "";
}
} // namespace

void parseIptcpRule(const iptcproxy_rule& rule, Row& r) {
  if (rule.target != nullptr) {
    r["target"] = TEXT(rule.target);
  } else {
    r["target"] = "";
  }

  if (rule.match) {
    r["match"] = "yes";
  } else {
    r["match"] = "no";
  }

  if (rule.match && rule.match_data.valid) {
    r["src_port"] = std::to_string(rule.match_data.spts[0]) + ':' +
                    std::to_string(rule.match_data.spts[1]);
    r["dst_port"] = std::to_string(rule.match_data.dpts[0]) + ':' +
                    std::to_string(rule.match_data.dpts[1]);
  } else {
    r["src_port"] = "";
    r["dst_port"] = "";
  }

  r["protocol"] =
      formatInvFlag(rule, IPTC_INV_PROTO) + INTEGER(rule.ip_data.proto);
  if (strlen(rule.ip_data.iniface)) {
    r["iniface"] =
        formatInvFlag(rule, IPTC_INV_VIA_IN) + TEXT(rule.ip_data.iniface);
  } else {
    r["iniface"] = "all";
  }

  if (strlen(rule.ip_data.outiface)) {
    r["outiface"] =
        formatInvFlag(rule, IPTC_INV_VIA_OUT) + TEXT(rule.ip_data.outiface);
  } else {
    r["outiface"] = "all";
  }

  r["src_ip"] =
      formatInvFlag(rule, IPTC_INV_SRCIP) + ipAsString(&rule.ip_data.src);
  r["dst_ip"] =
      formatInvFlag(rule, IPTC_INV_DSTIP) + ipAsString(&rule.ip_data.dst);
  r["src_mask"] = ipAsString(&rule.ip_data.smsk);
  r["dst_mask"] = ipAsString(&rule.ip_data.dmsk);

  char aux_char[2] = {0};
  std::string iniface_mask;
  for (int i = 0; i < IFNAMSIZ && rule.ip_data.iniface_mask[i] != 0x00; i++) {
    aux_char[0] = kHexMap[(int)rule.ip_data.iniface_mask[i] >> kMaskHighBits];
    aux_char[1] = kHexMap[(int)rule.ip_data.iniface_mask[i] & kMaskLowBits];
    iniface_mask += aux_char[0];
    iniface_mask += aux_char[1];
  }

  r["iniface_mask"] = TEXT(iniface_mask);
  std::string outiface_mask = "";
  for (int i = 0; i < IFNAMSIZ && rule.ip_data.outiface_mask[i] != 0x00; i++) {
    aux_char[0] = kHexMap[(int)rule.ip_data.outiface_mask[i] >> kMaskHighBits];
    aux_char[1] = kHexMap[(int)rule.ip_data.outiface_mask[i] & kMaskLowBits];
    outiface_mask += aux_char[0];
    outiface_mask += aux_char[1];
  }
  r["outiface_mask"] = TEXT(outiface_mask);
}

void genIPTablesRules(const std::string &filter, QueryData &results) {
  Row r;
  r["filter_name"] = filter;

  // Initialize the access to iptc
  auto handle = iptcproxy_init(filter.c_str());
  if (handle == nullptr) {
    return;
  }

  // Iterate through chains
  for (auto chain = iptcproxy_first_chain(handle);
      chain != nullptr;
      chain = iptcproxy_next_chain(handle)) {
    r["chain"] = TEXT(chain->chain);

    if (chain->policy != nullptr) {
      r["policy"] = TEXT(chain->policy);
      r["packets"] = INTEGER(chain->policy_data.pcnt);
      r["bytes"] = INTEGER(chain->policy_data.bcnt);
    } else {
      r["policy"] = "";
      r["packets"] = "0";
      r["bytes"] = "0";
    }

    // Iterating through all the rules per chain
    for (auto rule = iptcproxy_first_rule(chain->chain, handle);
         rule != nullptr;
         rule = iptcproxy_next_rule(handle)) {
      Row ruleRow{r};
      parseIptcpRule(*rule, ruleRow);
      results.push_back(std::move(ruleRow));
    } // Rule iteration
    results.push_back(r);
  } // Chain iteration

  iptcproxy_free(handle);
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
