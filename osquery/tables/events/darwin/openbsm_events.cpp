/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <arpa/inet.h>

#include <unordered_map>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>

#include <osquery/events/darwin/openbsm.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {

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
  if (tok.tt.subj32_ex.tid.type == AU_IPv4) {
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

class OpenBSMProcEvSubscriber : public EventSubscriber<OpenBSMEventPublisher> {
 public:
  Status init() override {
    return Status(0);
  }

  void configure() override;

  Status Callback(const OpenBSMEventContextRef& ec,
                  const OpenBSMSubscriptionContextRef& sc);

 private:
  Status handleExec(const OpenBSMEventContextRef& ec);
  Status handleFork(const OpenBSMEventContextRef& ec);
  Status handleExit(const OpenBSMEventContextRef& ec);

  std::unordered_map<uint32_t, uint32_t> ppid_map;
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

REGISTER(OpenBSMProcEvSubscriber, "event_subscriber", "process_events");
REGISTER(OpenBSMSSHLoginSubscriber, "event_subscriber", "user_events");

void OpenBSMProcEvSubscriber::configure() {
  std::vector<size_t> event_ids{
      AUE_EXECVE,
      AUE_POSIX_SPAWN,
      AUE_FORK,
      AUE_VFORK,
      AUE_FORK1,
      AUE_DARWIN_RFORK,
      AUE_RFORK,
      AUE_EXIT,
  };
  for (const auto& evid : event_ids) {
    auto sc = createSubscriptionContext();
    sc->event_id = evid;
    subscribe(&OpenBSMProcEvSubscriber::Callback, sc);
  }
}

Status OpenBSMProcEvSubscriber::Callback(
    const OpenBSMEventContextRef& ec, const OpenBSMSubscriptionContextRef& sc) {
  switch (sc->event_id) {
  case AUE_EXECVE:
  case AUE_POSIX_SPAWN:
    return handleExec(ec);

  case AUE_FORK:
  case AUE_VFORK:
  case AUE_FORK1:
  case AUE_DARWIN_RFORK:
  case AUE_RFORK:
    return handleFork(ec);

  case AUE_EXIT:
    return handleExit(ec);
  }

  return Status(1, "Unexpected event");
}

Status OpenBSMProcEvSubscriber::handleExec(const OpenBSMEventContextRef& ec) {
  Row r;
  uint32_t pid = 0;

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
      pid = tok.tt.subj32.pid;
      break;
    case AUT_SUBJECT64:
      r["auid"] = INTEGER(tok.tt.subj64.auid);
      r["pid"] = INTEGER(tok.tt.subj64.pid);
      r["euid"] = INTEGER(tok.tt.subj64.euid);
      r["egid"] = INTEGER(tok.tt.subj64.egid);
      r["uid"] = INTEGER(tok.tt.subj64.ruid);
      r["gid"] = INTEGER(tok.tt.subj64.rgid);
      pid = tok.tt.subj32.pid;
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
    case AUT_ATTR32: {
      std::stringstream ss;
      ss << "0" << std::oct << tok.tt.attr32.mode;
      ss >> r["mode"];
      r["owner_uid"] = INTEGER(tok.tt.attr32.uid);
      r["owner_gid"] = INTEGER(tok.tt.attr32.gid);
      r["fsid"] = INTEGER(tok.tt.attr32.fsid);
      r["nid"] = INTEGER(tok.tt.attr32.nid);
      r["dev"] = INTEGER(tok.tt.attr32.dev);
      break;
    }
    case AUT_EXEC_ENV:
      for (size_t i = 0; i < tok.tt.execarg.count; ++i) {
        r["env"] += std::string(tok.tt.execenv.text[i]) + " ";
      }
      r["env_count"] = INTEGER(tok.tt.execarg.count);
      r["env_size"] = INTEGER(r["env"].length());
      break;
    }
  }
  r["uptime"] = INTEGER(getUptime());

  auto ppid = ppid_map.find(pid);
  if (ppid != ppid_map.end()) {
    r["parent"] = INTEGER(ppid->second);
  } else {
    /* If mapping doesn't exist no fork was captured. Not fatal. Ignoring. */
    r["parent"] = INTEGER(-1);
  }

  add(r);
  return Status::success();
}

Status OpenBSMProcEvSubscriber::handleFork(const OpenBSMEventContextRef& ec) {
  uint32_t ppid = 0; // Parent PID
  uint32_t cpid = 0; // Child PID

  for (const auto& tok : ec->tokens) {
    switch (tok.id) {
    /* The parent is the process issuing the syscall. Its PID is given on the
     * subject token.
     */
    case AUT_SUBJECT32:
      ppid = tok.tt.subj32.pid;
      break;
    case AUT_SUBJECT64:
      ppid = tok.tt.subj64.pid;
      break;
    case AUT_SUBJECT32_EX:
      ppid = tok.tt.subj32_ex.pid;
      break;
    case AUT_SUBJECT64_EX:
      ppid = tok.tt.subj64_ex.pid;
      break;

    /* Child PID is given as the first argument here. This could also be
     * extract from the return token as the child PID should be the return
     * value of the fork syscall given to the parent.
     */
    case AUT_ARG32:
      if (tok.tt.arg32.no == 0) {
        cpid = tok.tt.arg32.val;
      }
      break;
    case AUT_ARG64:
      if (tok.tt.arg64.no == 0) {
        cpid = tok.tt.arg64.val;
      }
      break;

    /* Check whether fork succeeded. Upon failure stop processing as no child
     * is created.
     */
    case AUT_RETURN32:
      if (tok.tt.ret32.status != 0) {
        return Status(0);
      }
      break;
    case AUT_RETURN64:
      if (tok.tt.ret64.err != 0) {
        return Status(0);
      }
    }
  }

  /* If we succeeded to to capture both parent and child PIDs add them to the
   * mapping. This information should always be available, if not the event is
   * malformed.
   */
  if (ppid != 0 && cpid != 0) {
    ppid_map[cpid] = ppid;
    return Status(0);
  } else {
    return Status(1, "Malformed event");
  }
}

Status OpenBSMProcEvSubscriber::handleExit(const OpenBSMEventContextRef& ec) {
  /* When the process exits the mapping is no longer relevant as there won't be
   * more syscalls issued by it. The PID most come in the subject header.
   */
  for (const auto& tok : ec->tokens) {
    switch (tok.id) {
    case AUT_SUBJECT32:
      ppid_map.erase(tok.tt.subj32.pid);
      return Status(0);
    case AUT_SUBJECT64:
      ppid_map.erase(tok.tt.subj64.pid);
      return Status(0);
    case AUT_SUBJECT32_EX:
      ppid_map.erase(tok.tt.subj32_ex.pid);
      return Status(0);
    case AUT_SUBJECT64_EX:
      ppid_map.erase(tok.tt.subj64_ex.pid);
      return Status(0);
    }
  }

  /* If the PID wasn't found this event is malformed. */
  return Status(1, "Malformed event");
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
  r["uptime"] = INTEGER(getUptime());
  add(r);
  return Status(0);
}
} // namespace osquery
