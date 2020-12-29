/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>

#include <arpa/inet.h>
#include <libproc.h>
#include <stdio.h>

#include <iostream>

#include <osquery/core/flags.h>
#include <osquery/events/darwin/openbsm.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {

DECLARE_bool(audit_allow_sockets);
DECLARE_bool(disable_audit);

static std::string getIpFromToken(const tokenstr_t& tok) {
  char ip_str[INET6_ADDRSTRLEN] = {0};
  if (tok.tt.sockinet_ex32.family == 2) {
    struct in_addr ipv4;
    ipv4.s_addr = static_cast<in_addr_t>(*tok.tt.sockinet_ex32.addr);
    return std::string(inet_ntop(AF_INET, &ipv4, ip_str, INET6_ADDRSTRLEN));
  } else {
    struct in6_addr ipv6;
    memcpy(&ipv6, tok.tt.sockinet_ex32.addr, sizeof(ipv6));
    return std::string(inet_ntop(AF_INET6, &ipv6, ip_str, INET6_ADDRSTRLEN));
  }
}

static std::string getPathFromPid(int pid) {
  char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {0};

  int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
  if (ret > 0) {
    return std::string(pathbuf);
  } else {
    return "";
  }
}

class OpenBSMNetEvSubscriber : public EventSubscriber<OpenBSMEventPublisher> {
 public:
  Status init() override;

  void configure() override;

  Status Callback(const OpenBSMEventContextRef& ec,
                  const OpenBSMSubscriptionContextRef& sc);
};

REGISTER(OpenBSMNetEvSubscriber, "event_subscriber", "socket_events");

Status OpenBSMNetEvSubscriber::init() {
  if (!FLAGS_audit_allow_sockets || FLAGS_disable_audit) {
    return Status::failure("Subscriber disabled via configuration");
  }
  return Status::success();
}

void OpenBSMNetEvSubscriber::configure() {
  std::vector<size_t> event_ids{AUE_CONNECT, AUE_BIND};
  for (const auto& evid : event_ids) {
    auto sc = createSubscriptionContext();
    sc->event_id = evid;
    subscribe(&OpenBSMNetEvSubscriber::Callback, sc);
  }
}

Status OpenBSMNetEvSubscriber::Callback(
    const OpenBSMEventContextRef& ec, const OpenBSMSubscriptionContextRef& sc) {
  Row r;
  uint32_t pid = 0;

  for (const auto& tok : ec->tokens) {
    if (tok.id != AUT_SOCKUNIX) {
      switch (tok.id) {
      case AUT_HEADER32:
        r["time"] = BIGINT(tok.tt.hdr32.s);
        if (tok.tt.hdr32.e_type == AUE_CONNECT) {
          r["action"] = "connect";
        } else if (tok.tt.hdr32.e_type == AUE_BIND) {
          r["action"] = "bind";
        } else {
          continue;
        }
        break;
      case AUT_HEADER32_EX:
        r["time"] = BIGINT(tok.tt.hdr32_ex.s);
        if (tok.tt.hdr32_ex.e_type == AUE_CONNECT) {
          r["action"] = "connect";
        } else if (tok.tt.hdr32_ex.e_type == AUE_BIND) {
          r["action"] = "bind";
        } else {
          continue;
        }
        break;
      case AUT_HEADER64:
      case AUT_HEADER64_EX:
        r["time"] = BIGINT(tok.tt.hdr64_ex.s);
        if (tok.tt.hdr64_ex.e_type == AUE_CONNECT) {
          r["action"] = "connect";
        } else if (tok.tt.hdr64_ex.e_type == AUE_BIND) {
          r["action"] = "bind";
        } else {
          continue;
        }
        break;
      case AUT_ARG32: {
        std::stringstream stream;
        stream << std::hex << tok.tt.arg32.val;
        std::string result(stream.str());
        r["fd"] = result;
        break;
      }
      case AUT_ARG64: {
        std::stringstream stream;
        stream << std::hex << tok.tt.arg64.val;
        std::string result(stream.str());
        r["fd"] = result;
        break;
      }
      case AUT_SUBJECT32:
        r["auid"] = INTEGER(tok.tt.subj32.auid);
        r["pid"] = INTEGER(tok.tt.subj32.pid);
        pid = tok.tt.subj32.pid;
        break;
      case AUT_SUBJECT64:
        r["auid"] = INTEGER(tok.tt.subj64.auid);
        r["pid"] = INTEGER(tok.tt.subj64.pid);
        pid = tok.tt.subj32.pid;
        break;
      case AUT_SUBJECT32_EX:
        r["auid"] = INTEGER(tok.tt.subj32_ex.auid);
        r["pid"] = INTEGER(tok.tt.subj32_ex.pid);
        pid = tok.tt.subj32_ex.pid;
        break;
      case AUT_RETURN32: {
        int error = 0;
        if (au_bsm_to_errno(tok.tt.ret32.status, &error) == 0) {
          if (error == 0) {
            r["success"] = INTEGER(1);
          } else {
            r["success"] = INTEGER(0);
          }
        } else
          r["success"] = INTEGER(0);
        break;
      }
      case AUT_RETURN64: {
        int error = 0;
        if (au_bsm_to_errno(tok.tt.ret64.err, &error) == 0) {
          if (error == 0) {
            r["success"] = INTEGER(1);
          } else {
            r["success"] = INTEGER(0);
          }
        } else
          r["success"] = INTEGER(0);
        break;
      }
      case AUT_SOCKINET32: {
        if (r["action"] == "bind") {
          r["remote_address"] = "0";
          r["remote_port"] = "0";
          r["local_address"] = getIpFromToken(tok);
          r["local_port"] = INTEGER(ntohs(tok.tt.sockinet_ex32.port));
        } else {
          r["remote_address"] = getIpFromToken(tok);
          r["remote_port"] = INTEGER(ntohs(tok.tt.sockinet_ex32.port));
          r["local_address"] = "0";
          r["local_port"] = "0";
        }
        if (tok.tt.sockinet_ex32.family == 2) {
          r["family"] = INTEGER(2);
        } else if (tok.tt.sockinet_ex32.family == 26) {
          r["family"] = INTEGER(10);
        } else {
          r["family"] = INTEGER(0);
        }
        break;
      }
      case AUT_SOCKINET128: {
        if (r["action"] == "bind") {
          r["remote_address"] = "0";
          r["remote_port"] = "0";
          r["local_address"] = getIpFromToken(tok);
          r["local_port"] = INTEGER(ntohs(tok.tt.sockinet_ex32.port));
        } else {
          r["remote_address"] = getIpFromToken(tok);
          r["remote_port"] = INTEGER(ntohs(tok.tt.sockinet_ex32.port));
          r["local_address"] = "0";
          r["local_port"] = "0";
        }
        if (tok.tt.sockinet_ex32.family == 2) {
          r["family"] = INTEGER(2);
        } else if (tok.tt.sockinet_ex32.family == 26) {
          r["family"] = INTEGER(10);
        } else {
          r["family"] = INTEGER(0);
        }
        break;
      }
      }
    }
  }

  auto remote_address = r.find("remote_address");
  if (remote_address != r.end()) {
    r["uptime"] = INTEGER(getUptime());
    r["path"] = getPathFromPid(pid);
    add(r);
  }

  return Status::success();
}

} // namespace osquery
