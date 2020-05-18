/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <bsm/libbsm.h>
#include <security/audit/audit_ioctl.h>
#include <sys/ioctl.h>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/events/darwin/openbsm.h"

namespace osquery {

const int kQLimit = 512;

DECLARE_bool(disable_audit);
DECLARE_bool(audit_allow_process_events);
DECLARE_bool(audit_allow_sockets);
DECLARE_bool(audit_allow_user_events);
DECLARE_bool(audit_allow_fim_events);

REGISTER(OpenBSMEventPublisher, "event_publisher", "openbsm");

static Status configureAuditPipe(FILE* au_pipe) {
  auto au_fd = fileno(au_pipe);
  audit_pipe_ = nullptr;

  int pr_sel_mode = AUDITPIPE_PRESELECT_MODE_LOCAL;
  if (ioctl(au_fd, AUDITPIPE_SET_PRESELECT_MODE, &pr_sel_mode) == -1) {
    LOG(WARNING) << "The auditpipe:ioctl AUDITPIPE_SET_PRESELECT_MODE failed";
    fclose(au_pipe);
    return Status(1, "Failed to set AUDITPIPE_SET_PRESELECT_MODE");
  }

  if (ioctl(au_fd, AUDITPIPE_SET_QLIMIT, &kQLimit) == -1) {
    LOG(INFO) << "The auditpipe:ioctl AUDITPIPE_SET_QLIMIT failed";
  }

  struct au_class_ent* ace;
  au_mask_t pr_flags = {0, 0};
  std::vector<std::string> ev_classes;

  if (true == FLAGS_audit_allow_process_events) {
    // capture process events
    ev_classes.push_back("pc");
  }

  if (true == FLAGS_audit_allow_sockets) {
    // capture network events
    ev_classes.push_back("nt");
  }

  if (true == FLAGS_audit_allow_user_events) {
    // capture user (login, autherization etc...) events
    ev_classes.push_back("lo");
    ev_classes.push_back("aa");
    ev_classes.push_back("ad");
  }

  if (true == FLAGS_audit_allow_fim_events)
    // capture file events
    ev_classes.push_back("fc");
    ev_classes.push_back("fd");
    ev_classes.push_back("fw");
    ev_classes.push_back("fr");
    ev_classes.push_back("fa");
    ev_classes.push_back("fm");
  }

  while ((ace = getauclassent()) != nullptr) {
    for (auto& cl : ev_classes) {
      if (cl == ace->ac_name) {
        ADD_TO_MASK(&pr_flags, ace->ac_class, AU_PRS_BOTH);
        break;
      }
    }
  }
  endauclass();

  au_mask_t na_pr_flags = pr_flags;

  if (ioctl(au_fd, AUDITPIPE_SET_PRESELECT_FLAGS, &pr_flags) == -1) {
    LOG(WARNING) << "The auditpipe:ioctl AUDITPIPE_SET_PRESELECT_FLAGS failed";
    fclose(au_pipe);
    return Status(1, "Failed to set AUDITPIPE_SET_PRESELECT_FLAGS");
  }

  if (ioctl(au_fd, AUDITPIPE_SET_PRESELECT_NAFLAGS, &na_pr_flags) == -1) {
    LOG(WARNING)
        << "The auditpipe:ioctl AUDITPIPE_SET_PRESELECT_NAFLAGS failed";
    fclose(au_pipe);
    return Status(1, "Failed to set AUDITPIPE_SET_PRESELECT_NAFLAGS");
  }

  audit_pipe_ = au_pipe;
  return Status(0);
}

Status OpenBSMEventPublisher::setUp() {
  if (FLAGS_disable_audit) {
    return Status(1, "Publisher disabled via configuration");
  }
  audit_pipe_ = fopen("/dev/auditpipe", "r");
  if (audit_pipe_ == nullptr) {
    LOG(WARNING) << "The auditpipe couldn't be opened.";
    return Status(1, "Could not open OpenBSM pipe");
  }

  return configureAuditPipe(audit_pipe_);
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
