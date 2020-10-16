/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <osquery/core/sql/row.h>
#include <osquery/logger/logger.h>
extern "C" {
#include <osquery/tables/networking/linux/iptc_proxy.h>
}
namespace osquery {
namespace tables {

void parseIptcpRule(const iptcproxy_rule& rule, Row& r);

iptcproxy_rule getIpEntryContent() {
  static iptcproxy_rule ip_rule;

  ip_rule.target = nullptr;
  ip_rule.match = false;
  ip_rule.match_data.valid = false;

  ip_rule.ip_data.proto = 6;
  memset(ip_rule.ip_data.iniface, 0, IFNAMSIZ);
  strcpy(ip_rule.ip_data.outiface, "eth0");
  inet_aton("123.123.123.123", &ip_rule.ip_data.src);
  inet_aton("45.45.45.45", &ip_rule.ip_data.dst);
  ip_rule.ip_data.invflags = IPTC_INV_DSTIP;
  inet_aton("250.251.252.253", &ip_rule.ip_data.smsk);
  inet_aton("253.252.251.250", &ip_rule.ip_data.dmsk);
  memset(ip_rule.ip_data.iniface_mask, 0xfe, IFNAMSIZ);
  memset(ip_rule.ip_data.outiface_mask, 0xfa, IFNAMSIZ);
  ip_rule.ip_data.iniface_mask[IFNAMSIZ - 1] = 0x00;
  ip_rule.ip_data.outiface_mask[IFNAMSIZ - 1] = 0x00;
  return ip_rule;
}

Row getIpEntryExpectedResults() {
  Row row;

  row["target"] = "";
  row["match"] = "no";
  row["dst_port"] = "";
  row["src_port"] = "";
  row["protocol"] = "6";
  row["iniface"] = "all";
  row["outiface"] = "eth0";
  row["src_ip"] = "123.123.123.123";
  row["dst_ip"] = "!45.45.45.45";
  row["src_mask"] = "250.251.252.253";
  row["dst_mask"] = "253.252.251.250";
  row["iniface_mask"] = "FEFEFEFEFEFEFEFEFEFEFEFEFEFEFE";
  row["outiface_mask"] = "FAFAFAFAFAFAFAFAFAFAFAFAFAFAFA";

  return row;
}

class IptablesTests : public testing::Test {};

TEST_F(IptablesTests, test_iptables_ip_entry) {
  Row row;
  parseIptcpRule(getIpEntryContent(), row);
  EXPECT_EQ(row, getIpEntryExpectedResults());
}
} // namespace tables
} // namespace osquery
