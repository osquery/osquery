/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <stdio.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <ctime>

#include <sstream>

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>

#include "osquery/events/linux/auditdnetlink.h"
#include "osquery/tests/test_util.h"

namespace osquery {

DECLARE_bool(audit_allow_unix);

using StringMap = std::map<std::string, std::string>;

/// Generates a fake audit id
std::string generateAuditId(std::uint32_t event_id) noexcept {
  std::stringstream str_helper;
  str_helper << std::time(nullptr) << ".000:" << event_id;

  return str_helper.str();
}

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
      AuditdNetlinkParser::ParseAuditReply(reply, audit_event_record);
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
  auto decoded_normal = DecodeAuditPathValues("\"/bin/ls\"");
  EXPECT_EQ(decoded_normal, "/bin/ls");

  // If the first char is not '"', the value is expected to be hex-encoded.
  auto decoded_hex = DecodeAuditPathValues("736C6565702031");
  EXPECT_EQ(decoded_hex, "sleep 1");

  // When the hex fails to decode the input value is returned as the result.
  auto decoded_fail = DecodeAuditPathValues("7");
  EXPECT_EQ(decoded_fail, "7");
}

size_t kAuditCounter{0};

bool SimpleUpdate(size_t t, const StringMap& f, StringMap& m) {
  kAuditCounter++;
  for (const auto& i : f) {
    m[i.first] = i.second;
  }
  return true;
}

}
