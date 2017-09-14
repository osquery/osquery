/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <bsm/libbsm.h>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/events/darwin/openbsm.h"


namespace osquery {

/// The OpenBSM subsystem may have a performance impact on the system.
FLAG(bool,
     disable_audit,
     true,
     "Disable receiving events from the audit subsystem");

REGISTER(OpenBSMEventPublisher, "event_publisher", "openbsm");

Status OpenBSMEventPublisher::setUp() {
  if (FLAGS_disable_audit) {
    return Status(1, "Publisher disabled via configuration");
  }
  audit_pipe_ = fopen("/dev/auditpipe", "r");
  if (audit_pipe_ == nullptr) {
    LOG(WARNING) << "The auditpipe couldn't be opened.";
    return Status(1, "Could not open OpenBSM pipe");
  }
  return Status(0);
}

void OpenBSMEventPublisher::configure() {}

void OpenBSMEventPublisher::tearDown() {
  if (audit_pipe_ != nullptr) {
    fclose(audit_pipe_);
    audit_pipe_ = nullptr;
  }
}

Status OpenBSMEventPublisher::run() {
  if (audit_pipe_ == nullptr) {
    return Status(1, "No open audit_pipe");
  }
  tokenstr_t tok;
  auto reclen = 0;
  auto bytesread = 0;
  auto event_id = 0;
  auto buffer = static_cast<unsigned char*>(nullptr);
  std::vector<tokenstr_t> tokens{};

  while (!isEnding() && (reclen = au_read_rec(audit_pipe_, &buffer)) != -1) {
    bytesread = 0;

    while (bytesread < reclen) {
      if (au_fetch_tok(&tok, buffer + bytesread, reclen - bytesread) == -1) {
        break;
      }
      switch (tok.id) {
      case AUT_HEADER32:
        event_id = tok.tt.hdr32_ex.e_type;
        break;
      case AUT_HEADER32_EX:
        event_id = tok.tt.hdr32_ex.e_type;
        break;
      case AUT_HEADER64:
        event_id = tok.tt.hdr64.e_type;
        break;
      case AUT_HEADER64_EX:
        event_id = tok.tt.hdr64_ex.e_type;
        break;
      }
      tokens.push_back(tok);
      bytesread += tok.len;
    }
    // We probably don't need a lambda here but it's useful to put debug
    // lines in to validate destruction.
    std::shared_ptr<unsigned char> sp_buffer(
        buffer, [](unsigned char* p) { delete p; });
    auto ec = createEventContext();
    ec->event_id = event_id;
    ec->tokens = tokens;
    ec->buffer = sp_buffer;
    fire(ec);
    tokens.clear();
    event_id = 0;
  }
  return Status(0);
}

bool OpenBSMEventPublisher::shouldFire(const OpenBSMSubscriptionContextRef& mc,
                                       const OpenBSMEventContextRef& ec) const {
  if (mc->event_id == ec->event_id) {
    return true;
  }
  return false;
}
} // namespace osquery
