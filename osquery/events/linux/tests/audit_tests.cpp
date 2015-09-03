/*
 *  Copyright (c) 2014, Facebook, Inc.
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
#include <osquery/tables.h>

#include "osquery/events/linux/audit.h"
#include "osquery/core/test_util.h"

namespace osquery {

/// Internal audit publisher testable methods.
extern bool handleAuditReply(const struct audit_reply& reply,
                             AuditEventContextRef& ec);

/// Internal audit subscriber (process events) testable methods.
extern std::string decodeAuditValue(const std::string& e);
extern Status validAuditState(int type, AuditProcessEventState& state);

class AuditTests : public testing::Test {
 protected:
  void SetUp() { Row().swap(row_); }

 protected:
  Row row_;
};

TEST_F(AuditTests, test_handle_reply) {
  // Create the input structures.
  struct audit_reply reply;
  auto ec = std::make_shared<AuditEventContext>();

  // A 'fake' audit message.
  std::string message =
      "audit(1440542781.644:403030): argc=3 a0=\"/bin/sh\" a1=\"-c\" a2=\"h\"";

  reply.type = 1;
  reply.len = message.size();
  reply.message = (char*)malloc(sizeof(char) * (message.size() + 1));
  memset((void*)reply.message, 0, message.size() + 1);
  memcpy((void*)reply.message, message.c_str(), message.size());

  // Perform the parsing.
  handleAuditReply(reply, ec);
  free((char*)reply.message);

  EXPECT_EQ(reply.type, ec->type);
  EXPECT_EQ(ec->fields.size(), 4);
  EXPECT_EQ(ec->fields.count("argc"), 1);
  EXPECT_EQ(ec->fields["argc"], "3");
  EXPECT_EQ(ec->fields["a0"], "\"/bin/sh\"");
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

TEST_F(AuditTests, test_valid_audit_state) {
  AuditProcessEventState state = STATE_SYSCALL;

  // The first state must be a syscall.
  EXPECT_TRUE(validAuditState(STATE_SYSCALL, state));
  EXPECT_EQ(state, STATE_EXECVE);

  // Followed by an EXECVE, CWD, or PATH
  EXPECT_TRUE(validAuditState(STATE_EXECVE, state));
  EXPECT_EQ(state, STATE_CWD);
  EXPECT_TRUE(validAuditState(STATE_CWD, state));
  EXPECT_EQ(state, STATE_PATH);
  EXPECT_TRUE(validAuditState(STATE_PATH, state));
  // Finally, the state is reset to syscall.
  EXPECT_EQ(state, STATE_SYSCALL);
}

TEST_F(AuditTests, test_valid_audit_state_exceptions) {
  AuditProcessEventState state = STATE_SYSCALL;
  validAuditState(STATE_SYSCALL, state);

  // Now allow for other acceptable transitions.
  EXPECT_TRUE(validAuditState(STATE_PATH, state));
  EXPECT_EQ(state, STATE_SYSCALL);

  state = STATE_SYSCALL;
  validAuditState(STATE_SYSCALL, state);
  EXPECT_TRUE(validAuditState(STATE_PATH, state));
  EXPECT_EQ(state, STATE_SYSCALL);
}

TEST_F(AuditTests, test_valid_audit_state_failues) {
  // Now check invalid states.
  AuditProcessEventState state = STATE_SYSCALL;
  EXPECT_FALSE(validAuditState(STATE_EXECVE, state));
  EXPECT_FALSE(validAuditState(STATE_CWD, state));
  EXPECT_FALSE(validAuditState(STATE_PATH, state));

  // Two syscalls in a row: invalid.
  state = STATE_SYSCALL;
  validAuditState(STATE_SYSCALL, state);
  EXPECT_FALSE(validAuditState(STATE_SYSCALL, state));

  // A cwd must come after an exec.
  state = STATE_SYSCALL;
  validAuditState(STATE_SYSCALL, state);
  EXPECT_FALSE(validAuditState(STATE_CWD, state));

  // Two execs in a row: invalid.
  state = STATE_SYSCALL;
  validAuditState(STATE_SYSCALL, state);
  validAuditState(STATE_EXECVE, state);
  EXPECT_FALSE(validAuditState(STATE_EXECVE, state));
}
}
