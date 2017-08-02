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

#include <osquery/events.h>

#include "osquery/events/darwin/openbsm.h"

namespace osquery {

static inline void OpenBSM_AUT_SUBJECT32_EX(Row& r, const tokenstr_t& tok) {
  if (tok.id != AUT_SUBJECT32_EX) {
    return;
  }
  r["pid"] = INTEGER(tok.tt.subj32_ex.pid);
  r["uid"] = INTEGER(tok.tt.subj32_ex.ruid);
  r["gid"] = INTEGER(tok.tt.subj32_ex.rgid);
  r["euid"] = INTEGER(tok.tt.subj32_ex.euid);
  r["egid"] = INTEGER(tok.tt.subj32_ex.egid);
}

static inline unsigned long decimalIntToOctInt(unsigned long x) {
  auto ret = 0;
  for (auto i = 1; x > 0; i *= 10) {
    ret += (x & 0x7) * i;
    x >>= 3;
  }
  return ret;
}

class OpenBSMExecVESubscriber : public EventSubscriber<OpenBSMEventPublisher> {
 public:
  Status init() override {
    return Status(0);
  }

  void configure() override;

  Status Callback(const OpenBSMEventContextRef& ec,
                  const OpenBSMSubscriptionContextRef& sc);
};

class OpenBSMSSHLoginSubscriber
    : public EventSubscriber<OpenBSMEventPublisher> {
 public:
  Status init() override {
    return Status(0);
  }

  void configure() override;

  Status Callback(const OpenBSMEventContextRef& ec,
                  const OpenBSMSubscriptionContextRef& sc);
};

REGISTER(OpenBSMExecVESubscriber,
         "event_subscriber",
         "process_execution_events");
REGISTER(OpenBSMSSHLoginSubscriber,
         "event_subscriber",
         "local_ssh_login_events");

void OpenBSMExecVESubscriber::configure() {
  auto sc = createSubscriptionContext();
  sc->event_id = 23;
  subscribe(&OpenBSMExecVESubscriber::Callback, sc);
}

Status OpenBSMExecVESubscriber::Callback(
    const OpenBSMEventContextRef& ec, const OpenBSMSubscriptionContextRef& sc) {
  Row r;
  for (const auto& tok : ec->tokens) {
    switch (tok.id) {
    case AUT_HEADER32:
      r["time"] = BIGINT(tok.tt.hdr32.s);
      break;
    case AUT_HEADER32_EX:
      r["time"] = BIGINT(tok.tt.hdr32_ex.s);
      break;
    case AUT_HEADER64:
    case AUT_HEADER64_EX:
      r["time"] = BIGINT(tok.tt.hdr64_ex.s);
      break;
    case AUT_SUBJECT32:
      r["pid"] = INTEGER(tok.tt.subj32.pid);
      r["euid"] = INTEGER(tok.tt.subj32.euid);
      r["egid"] = INTEGER(tok.tt.subj32.egid);
      r["ruid"] = INTEGER(tok.tt.subj32.ruid);
      r["rgid"] = INTEGER(tok.tt.subj32.rgid);
      break;
    case AUT_SUBJECT64:
      r["pid"] = INTEGER(tok.tt.subj64.pid);
      r["euid"] = INTEGER(tok.tt.subj64.euid);
      r["egid"] = INTEGER(tok.tt.subj64.egid);
      r["ruid"] = INTEGER(tok.tt.subj64.ruid);
      r["rgid"] = INTEGER(tok.tt.subj64.rgid);
      break;
    case AUT_SUBJECT32_EX:
      OpenBSM_AUT_SUBJECT32_EX(r, tok);
      break;
    case AUT_RETURN32:
      r["status"] = INTEGER(static_cast<unsigned long>(tok.tt.ret32.status));
      break;
    case AUT_RETURN64:
      r["status"] = INTEGER(tok.tt.ret64.err);
      break;
    case AUT_EXEC_ARGS:
      for (auto i = static_cast<unsigned int>(0); i < tok.tt.execarg.count;
           ++i) {
        r["args"] += std::string(tok.tt.execarg.text[i]) + " ";
      }
      break;
    case AUT_PATH:
      r["path"] = std::string(tok.tt.path.path);
      break;
    case AUT_ATTR32:
      r["file_mode"] = INTEGER(decimalIntToOctInt(tok.tt.attr32.mode));
      r["owner_uid"] = INTEGER(tok.tt.attr32.uid);
      r["owner_gid"] = INTEGER(tok.tt.attr32.gid);
      r["fsid"] = INTEGER(tok.tt.attr32.fsid);
      r["nid"] = INTEGER(tok.tt.attr32.nid);
      r["dev"] = INTEGER(tok.tt.attr32.dev);
      break;
    }
  }
  add(r);
  return Status(0, "OK");
}

void OpenBSMSSHLoginSubscriber::configure() {
  auto sc = createSubscriptionContext();
  sc->event_id = 32800;
  subscribe(&OpenBSMSSHLoginSubscriber::Callback, sc);
}

Status OpenBSMSSHLoginSubscriber::Callback(
    const OpenBSMEventContextRef& ec, const OpenBSMSubscriptionContextRef& sc) {
  Row r;
  for (const auto& tok : ec->tokens) {
    switch (tok.id) {
    case AUT_HEADER32:
      r["time"] = BIGINT(tok.tt.hdr32.s);
      break;
    case AUT_HEADER32_EX:
      r["time"] = BIGINT(tok.tt.hdr32_ex.s);
      break;
    case AUT_HEADER64:
    case AUT_HEADER64_EX:
      r["time"] = BIGINT(tok.tt.hdr64_ex.s);
      break;
    case AUT_SUBJECT32_EX:
      OpenBSM_AUT_SUBJECT32_EX(r, tok);
      break;
    }
  }
  add(r);
  return Status(0);
}
} // namespace osquery
