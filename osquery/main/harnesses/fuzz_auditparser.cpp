/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "osquery/events/linux/auditdnetlink.h"

#include <osquery/main/harnesses/fuzz_utils.h>

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string message;
  message.resize(size);
  std::memcpy(&message[0], data, size);

  struct audit_reply reply;
  reply.type = 1;
  reply.len = message.size();
  reply.message = message.c_str();

  std::string_view message_view(message);

  auto subtype = osquery::AuditdNetlinkParser::ParseAuditRecordSubtype(
      reply.type, message_view);

  osquery::AuditEventRecord audit_event_record = {};
  osquery::AuditdNetlinkParser::ParseAuditReply(
      reply, subtype, audit_event_record);

  return 0;
}
