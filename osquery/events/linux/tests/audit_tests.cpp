/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <stdio.h>

#include <gtest/gtest.h>

#include <osquery/events.h>
#include <osquery/flags.h>
#include <osquery/tables.h>

#include "osquery/events/linux/audit.h"
#include "osquery/tests/test_util.h"

namespace osquery {

DECLARE_bool(audit_allow_unix);

/// Internal audit publisher testable methods.
extern bool handleAuditReply(const struct audit_reply& reply,
                             AuditEventContextRef& ec);

/// Internal audit subscriber (socket events) testable methods.
extern void parseSockAddr(const std::string& saddr, Row& r);

class AuditTests : public testing::Test {
 protected:
  void SetUp() override {
    Row().swap(row_);
  }

 protected:
  Row row_;
};

TEST_F(AuditTests, test_handle_reply) {
  // Create the input structures.
  struct audit_reply reply;
  auto ec = std::make_shared<AuditEventContext>();

  // A 'fake' audit message.
  std::string message =
      "audit(1440542781.644:403030): argc=3 a0=\"H=1 \" a1=\"/bin/sh\" a2=c";

  reply.type = 1;
  reply.len = message.size();
  reply.message = (char*)malloc(sizeof(char) * (message.size() + 1));
  memset((void*)reply.message, 0, message.size() + 1);
  memcpy((void*)reply.message, message.c_str(), message.size());

  // Perform the parsing.
  handleAuditReply(reply, ec);
  free((char*)reply.message);

  EXPECT_EQ(reply.type, ec->type);
  EXPECT_EQ(1440542781U, ec->time);
  EXPECT_EQ(403030U, ec->audit_id);
  EXPECT_EQ(ec->fields.size(), 4U);
  EXPECT_EQ(ec->fields.count("argc"), 1U);
  EXPECT_EQ(ec->fields["argc"], "3");
  EXPECT_EQ(ec->fields["a0"], "\"H=1 \"");
  EXPECT_EQ(ec->fields["a1"], "\"/bin/sh\"");
  EXPECT_EQ(ec->fields["a2"], "c");
}

TEST_F(AuditTests, test_audit_value_decode) {
  // In the normal case the decoding only removes '"' characters from the ends.
  auto decoded_normal = decodeAuditValue("\"/bin/ls\"");
  EXPECT_EQ(decoded_normal, "/bin/ls");

  // If the first char is not '"', the value is expected to be hex-encoded.
  auto decoded_hex = decodeAuditValue("736C6565702031");
  EXPECT_EQ(decoded_hex, "sleep 1");

  // When the hex fails to decode the input value is returned as the result.
  auto decoded_fail = decodeAuditValue("7");
  EXPECT_EQ(decoded_fail, "7");
}

size_t kAuditCounter{0};

bool SimpleUpdate(size_t t, const AuditFields& f, AuditFields& m) {
  kAuditCounter++;
  for (const auto& i : f) {
    m[i.first] = i.second;
  }
  return true;
}

TEST_F(AuditTests, test_audit_assembler) {
  // Test the queue correctness.
  AuditAssembler asmb;

  std::vector<size_t> expected_types{1, 2, 3};
  asmb.start(3, expected_types, nullptr);

  AuditFields expected_fields{{"1", "1"}};
  asmb.add(100U, 1, expected_fields);

  EXPECT_EQ(3U, asmb.capacity_);
  EXPECT_EQ(1U, asmb.queue_.size());

  EXPECT_EQ(expected_types, asmb.types_);
  // This will be empty since there is no update method.
  EXPECT_TRUE(asmb.m_[100].empty());

  expected_fields = {{"2", "2"}};
  asmb.add(100U, 1, expected_fields);

  // Again empty.
  EXPECT_TRUE(asmb.m_[100].empty());
  EXPECT_EQ(1U, asmb.mt_[100].size());

  asmb.add(100U, 2, expected_fields);
  asmb.add(100U, 3, expected_fields);
  EXPECT_TRUE(asmb.m_.empty());
  EXPECT_EQ(0U, asmb.queue_.size());

  // Flood with incomplete messages.
  for (size_t i = 0; i < 101; i++) {
    asmb.add(i, 1, {});
  }
  EXPECT_EQ(3U, asmb.queue_.size());
  EXPECT_EQ(3U, asmb.mt_.size());
  EXPECT_EQ(3U, asmb.m_.size());

  // Flood with complete messages.
  for (size_t i = 0; i < 101; i++) {
    asmb.add(i, 3, {});
    asmb.add(i, 1, {});
    asmb.add(i, 2, {});
  }

  // All of the queue items should have been removed.
  EXPECT_EQ(0U, asmb.queue_.size());
  EXPECT_EQ(0U, asmb.mt_.size());
  EXPECT_EQ(0U, asmb.m_.size());

  asmb.start(3U, {1, 2, 3}, &SimpleUpdate);
  EXPECT_FALSE(asmb.add(1, 1, expected_fields).is_initialized());
  EXPECT_EQ(1U, kAuditCounter);

  // Inject duplicate.
  EXPECT_FALSE(asmb.add(1, 1, expected_fields).is_initialized());
  EXPECT_EQ(2U, kAuditCounter);

  EXPECT_FALSE(asmb.add(1, 2, expected_fields).is_initialized());
  auto fields = asmb.add(1, 3, expected_fields);
  EXPECT_TRUE(fields.is_initialized());
  EXPECT_EQ(*fields, expected_fields);
}

TEST_F(AuditTests, test_parse_sock_addr) {
  Row r;
  std::string msg = "02001F907F0000010000000000000000";
  parseSockAddr(msg, r);
  ASSERT_FALSE(r["remote_address"].empty());
  EXPECT_EQ(r["remote_address"], "127.0.0.1");
  EXPECT_EQ(r["family"], "2");
  EXPECT_EQ(r["remote_port"], "8080");

  Row r3;
  std::string msg2 = "0A001F9100000000FE80000000000000022522FFFEB03684000000";
  parseSockAddr(msg2, r3);
  ASSERT_FALSE(r3["remote_address"].empty());
  EXPECT_EQ(r3["remote_address"], "fe80:0000:0000:0000:0225:22ff:feb0:3684");
  EXPECT_EQ(r3["remote_port"], "8081");

  auto socket_flag = FLAGS_audit_allow_unix;
  FLAGS_audit_allow_unix = true;
  Row r4;
  std::string msg3 = "01002F746D702F6F7371756572792E656D0000";
  parseSockAddr(msg3, r4);
  ASSERT_FALSE(r4["socket"].empty());
  EXPECT_EQ(r4["socket"], "/tmp/osquery.em");

  msg3 = "0100002F746D702F6F7371756572792E656D";
  parseSockAddr(msg3, r4);
  EXPECT_EQ(r4["socket"], "/tmp/osquery.em");
  FLAGS_audit_allow_unix = socket_flag;
}
}
