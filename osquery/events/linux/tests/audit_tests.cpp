/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdio.h>

#include <gtest/gtest.h>

#include <osquery/events.h>
#include <osquery/flags.h>
#include <osquery/tables.h>

#include "osquery/events/linux/audit.h"
#include "osquery/events/linux/auditdnetlink.h"
#include "osquery/events/linux/tests/audit_tests_common.h"
#include "osquery/tests/test_util.h"

#include <cstdint>
#include <ctime>

namespace osquery {

DECLARE_bool(audit_allow_unix);

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
  // A 'fake' audit message.
  std::string message =
      "audit(1440542781.644:403030): argc=3 a0=\"H=1 \" a1=\"/bin/sh\" a2=c";

  struct audit_reply reply;
  reply.type = 1;
  reply.len = message.size();
  reply.message = (char*)malloc(sizeof(char) * (message.size() + 1));
  memset((void*)reply.message, 0, message.size() + 1);
  memcpy((void*)reply.message, message.c_str(), message.size());

  // Perform the parsing.
  AuditEventRecord audit_event_record = {};
  bool parser_status =
      AuditdNetlink::ParseAuditReply(reply, audit_event_record);
  EXPECT_EQ(parser_status, true);

  free((char*)reply.message);

  EXPECT_EQ(reply.type, audit_event_record.type);
  EXPECT_EQ("1440542781.644:403030", audit_event_record.audit_id);
  EXPECT_EQ(audit_event_record.fields.size(), 4U);
  EXPECT_EQ(audit_event_record.fields.count("argc"), 1U);
  EXPECT_EQ(audit_event_record.fields["argc"], "3");
  EXPECT_EQ(audit_event_record.fields["a0"], "\"H=1 \"");
  EXPECT_EQ(audit_event_record.fields["a1"], "\"/bin/sh\"");
  EXPECT_EQ(audit_event_record.fields["a2"], "c");
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
  std::string audit_id = generateAuditId(100U);

  std::vector<size_t> expected_types{1, 2, 3};
  asmb.start(3, expected_types, nullptr);

  AuditFields expected_fields{{"1", "1"}};
  asmb.add(audit_id, 1, expected_fields);

  EXPECT_EQ(3U, asmb.capacity_);
  EXPECT_EQ(1U, asmb.queue_.size());

  EXPECT_EQ(expected_types, asmb.types_);
  // This will be empty since there is no update method.
  EXPECT_TRUE(asmb.m_[audit_id].empty());

  expected_fields = {{"2", "2"}};
  asmb.add(audit_id, 1, expected_fields);

  // Again empty.
  EXPECT_TRUE(asmb.m_[audit_id].empty());
  EXPECT_EQ(1U, asmb.mt_[audit_id].size());

  asmb.add(audit_id, 2, expected_fields);
  asmb.add(audit_id, 3, expected_fields);
  EXPECT_TRUE(asmb.m_.empty());
  EXPECT_EQ(0U, asmb.queue_.size());

  // Flood with incomplete messages.
  for (std::uint32_t i = 0U; i < 101U; i++) {
    std::string temp_audit_id = generateAuditId(i);
    asmb.add(temp_audit_id, 1, {});
  }
  EXPECT_EQ(3U, asmb.queue_.size());
  EXPECT_EQ(3U, asmb.mt_.size());
  EXPECT_EQ(3U, asmb.m_.size());

  // Flood with complete messages.
  for (std::uint32_t i = 0U; i < 101U; i++) {
    std::string temp_audit_id = generateAuditId(i);

    asmb.add(temp_audit_id, 3, {});
    asmb.add(temp_audit_id, 1, {});
    asmb.add(temp_audit_id, 2, {});
  }

  // All of the queue items should have been removed.
  EXPECT_EQ(0U, asmb.queue_.size());
  EXPECT_EQ(0U, asmb.mt_.size());
  EXPECT_EQ(0U, asmb.m_.size());

  asmb.start(3U, {1, 2, 3}, &SimpleUpdate);

  std::string temp_audit_id = generateAuditId(1);
  EXPECT_FALSE(asmb.add(temp_audit_id, 1, expected_fields).is_initialized());

  EXPECT_EQ(1U, kAuditCounter);

  // Inject duplicate.
  EXPECT_FALSE(asmb.add(temp_audit_id, 1, expected_fields).is_initialized());
  EXPECT_EQ(2U, kAuditCounter);

  EXPECT_FALSE(asmb.add(temp_audit_id, 2, expected_fields).is_initialized());
  auto fields = asmb.add(temp_audit_id, 3, expected_fields);
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
