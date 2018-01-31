/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/logger.h>

#include <arpa/inet.h>
#include <libiptc/libiptc.h>

#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

void parseIpEntry(const ipt_ip *ip, Row &row);

ipt_ip* getIpEntryContent() {
  static ipt_ip ip_entry;

  ip_entry.proto = 6;
  memset(ip_entry.iniface, 0, IFNAMSIZ);
  strcpy(ip_entry.outiface, "eth0");
  inet_aton("123.123.123.123", &ip_entry.src);
  inet_aton("45.45.45.45", &ip_entry.dst);
  inet_aton("250.251.252.253", &ip_entry.smsk);
  inet_aton("253.252.251.250", &ip_entry.dmsk);
  memset(ip_entry.iniface_mask, 0xfe, IFNAMSIZ);
  memset(ip_entry.outiface_mask, 0xfa, IFNAMSIZ);
  ip_entry.iniface_mask[IFNAMSIZ-1] = 0x00;
  ip_entry.outiface_mask[IFNAMSIZ-1] = 0x00;
  return &ip_entry;
}

Row getIpEntryExpectedResults() {
  Row row;

  row["protocol"] = "6";
  row["iniface"] = "all";
  row["outiface"] = "eth0";
  row["src_ip"] = "123.123.123.123";
  row["dst_ip"] = "45.45.45.45";
  row["src_mask"] = "250.251.252.253";
  row["dst_mask"] = "253.252.251.250";
  row["iniface_mask"] = "FEFEFEFEFEFEFEFEFEFEFEFEFEFEFE";
  row["outiface_mask"] = "FAFAFAFAFAFAFAFAFAFAFAFAFAFAFA";

  return row;
}

class IptablesTests : public testing::Test {};

TEST_F(IptablesTests, test_iptables_ip_entry) {
  Row row;
  parseIpEntry(getIpEntryContent(), row);
  EXPECT_EQ(row, getIpEntryExpectedResults());
}
} // namespace tables
} // namespace osquery
