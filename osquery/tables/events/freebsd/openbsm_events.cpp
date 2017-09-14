/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <bsm/libbsm.h>

#include <osquery/events.h>
#include <osquery/logger.h>

#include "osquery/events/darwin/openbsm.h"

namespace osquery {

namespace tables {
extern long getUptime();
}

static inline void OpenBSM_AUT_SUBJECT32_EX(Row& r, const tokenstr_t& tok) {
  if (tok.id != AUT_SUBJECT32_EX) {
    return;
  }
  r["auid"] = INTEGER(tok.tt.subj32_ex.auid);
  r["pid"] = INTEGER(tok.tt.subj32_ex.pid);
  r["uid"] = INTEGER(tok.tt.subj32_ex.ruid);
  r["gid"] = INTEGER(tok.tt.subj32_ex.rgid);
  r["euid"] = INTEGER(tok.tt.subj32_ex.euid);
  r["egid"] = INTEGER(tok.tt.subj32_ex.egid);
  char ip_str[INET6_ADDRSTRLEN];
  if (tok.tt.proc32_ex.tid.type == AU_IPv4) {
    struct in_addr ipv4;
    ipv4.s_addr = static_cast<in_addr_t>(*tok.tt.subj32_ex.tid.addr);
    r["address"] =
        std::string(inet_ntop(AF_INET, &ipv4, ip_str, INET6_ADDRSTRLEN));
  } else {
    struct in6_addr ipv6;
    memcpy(&ipv6, tok.tt.subj32_ex.tid.addr, sizeof(ipv6));
    r["address"] =
        std::string(inet_ntop(AF_INET6, &ipv6, ip_str, INET6_ADDRSTRLEN));
  }
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

REGISTER(OpenBSMExecVESubscriber, "event_subscriber", "process_events");
REGISTER(OpenBSMSSHLoginSubscriber, "event_subscriber", "user_events");

void OpenBSMExecVESubscriber::configure() {
  std::vector<size_t> event_ids{
      23, // execve
      43190, // AUX_POSIX_SPAWN
  };
  for (const auto& evid : event_ids) {
    auto sc = createSubscriptionContext();
    sc->event_id = evid;
    subscribe(&OpenBSMExecVESubscriber::Callback, sc);
  }
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
      r["auid"] = INTEGER(tok.tt.subj32.auid);
      r["pid"] = INTEGER(tok.tt.subj32.pid);
      r["euid"] = INTEGER(tok.tt.subj32.euid);
      r["egid"] = INTEGER(tok.tt.subj32.egid);
      r["uid"] = INTEGER(tok.tt.subj32.ruid);
      r["gid"] = INTEGER(tok.tt.subj32.rgid);
      break;
    case AUT_SUBJECT64:
      r["auid"] = INTEGER(tok.tt.subj64.auid);
      r["pid"] = INTEGER(tok.tt.subj64.pid);
      r["euid"] = INTEGER(tok.tt.subj64.euid);
      r["egid"] = INTEGER(tok.tt.subj64.egid);
      r["uid"] = INTEGER(tok.tt.subj64.ruid);
      r["gid"] = INTEGER(tok.tt.subj64.rgid);
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
      for (size_t i = 0; i < tok.tt.execarg.count; ++i) {
        r["cmdline"] += std::string(tok.tt.execarg.text[i]) + " ";
      }
      r["cmdline_size"] = INTEGER(r["cmdline"].length());
      break;
    case AUT_PATH:
      r["path"] = std::string(tok.tt.path.path);
      break;
    case AUT_ATTR32:
      r["mode"] = INTEGER(decimalIntToOctInt(tok.tt.attr32.mode));
      r["owner_uid"] = INTEGER(tok.tt.attr32.uid);
      r["owner_gid"] = INTEGER(tok.tt.attr32.gid);
      r["fsid"] = INTEGER(tok.tt.attr32.fsid);
      r["nid"] = INTEGER(tok.tt.attr32.nid);
      r["dev"] = INTEGER(tok.tt.attr32.dev);
      break;
    case AUT_EXEC_ENV:
      for (size_t i = 0; i < tok.tt.execarg.count; ++i) {
        r["env"] += std::string(tok.tt.execenv.text[i]) + " ";
      }
      r["env_count"] = INTEGER(tok.tt.execarg.count);
      r["env_size"] = INTEGER(r["env"].length());
      break;
    }
  }
  r["uptime"] = INTEGER(tables::getUptime());
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
    case AUT_SUBJECT32:
      r["auid"] = INTEGER(tok.tt.subj32.auid);
      break;
    case AUT_SUBJECT32_EX:
      OpenBSM_AUT_SUBJECT32_EX(r, tok);
      break;
    case AUT_TEXT:
      r["message"] =
          "OpenSSH: " + std::string(tok.tt.text.text, tok.tt.text.len);
      break;
    }
  }
  r["uptime"] = INTEGER(tables::getUptime());
  add(r);
  return Status(0);
}
} // namespace osquery
