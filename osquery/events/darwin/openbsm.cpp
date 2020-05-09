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
#include <sys/select.h>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/events/darwin/openbsm.h"

namespace osquery {

const int kQLimit = 512;

DECLARE_bool(disable_audit);
DECLARE_bool(audit_allow_config);
DECLARE_bool(audit_allow_process_events);
DECLARE_bool(audit_allow_sockets);
DECLARE_bool(audit_allow_user_events);
DECLARE_bool(audit_allow_fim_events);

REGISTER(OpenBSMEventPublisher, "event_publisher", "openbsm");

Status OpenBSMEventPublisher::configureAuditPipe() {
  auto au_pipe = audit_pipe_;
  auto au_fd = fileno(au_pipe);
  int pr_sel_mode = AUDITPIPE_PRESELECT_MODE_LOCAL;

  audit_pipe_ = nullptr;

  if (ioctl(au_fd, AUDITPIPE_SET_PRESELECT_MODE, &pr_sel_mode) == -1) {
    LOG(WARNING) << "The auditpipe:ioctl AUDITPIPE_SET_PRESELECT_MODE failed";
    fclose(au_pipe);
    return Status::failure("Failed to set AUDITPIPE_SET_PRESELECT_MODE");
  }

  if (ioctl(au_fd, AUDITPIPE_SET_QLIMIT, &kQLimit) == -1) {
    LOG(INFO) << "The auditpipe:ioctl AUDITPIPE_SET_QLIMIT failed";
  }

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

  if (true == FLAGS_audit_allow_fim_events) {
    // capture file events
    ev_classes.push_back("fc");
    ev_classes.push_back("fd");
    ev_classes.push_back("fw");
    ev_classes.push_back("fr");
    ev_classes.push_back("fa");
    ev_classes.push_back("fm");
  }

  struct au_class_ent* ace = nullptr;
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
    return Status::failure("Failed to set AUDITPIPE_SET_PRESELECT_FLAGS");
  }

  if (ioctl(au_fd, AUDITPIPE_SET_PRESELECT_NAFLAGS, &na_pr_flags) == -1) {
    LOG(WARNING)
        << "The auditpipe:ioctl AUDITPIPE_SET_PRESELECT_NAFLAGS failed";
    fclose(au_pipe);
    return Status::failure("Failed to set AUDITPIPE_SET_PRESELECT_NAFLAGS");
  }

  audit_pipe_ = au_pipe;
  return Status::success();
}

Status OpenBSMEventPublisher::setUp() {
  if (FLAGS_disable_audit) {
    return Status::failure("Publisher disabled via configuration");
  }
  audit_pipe_ = fopen("/dev/auditpipe", "r");
  if (audit_pipe_ == nullptr) {
    LOG(WARNING) << "The auditpipe couldn't be opened.";
    return Status::failure("Could not open OpenBSM pipe");
  }

  return FLAGS_audit_allow_config ? configureAuditPipe() : Status::success();
}

void OpenBSMEventPublisher::configure() {}

void OpenBSMEventPublisher::tearDown() {
  if (audit_pipe_ != nullptr) {
    fclose(audit_pipe_);
    audit_pipe_ = nullptr;
  }
}

void OpenBSMEventPublisher::acquireMessages() {
  auto buffer = static_cast<unsigned char*>(nullptr);
  auto reclen = au_read_rec(audit_pipe_, &buffer);
  if (reclen <= 0) {
    return;
  }

  // We'll use these to dequeue below.
  tokenstr_t tok;
  std::vector<tokenstr_t> tokens{};

  auto event_id = 0;
  auto bytesread = 0;
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
  std::shared_ptr<unsigned char> sp_buffer(buffer,
                                           [](unsigned char* p) { delete p; });

  auto ec = createEventContext();
  ec->event_id = event_id;
  ec->tokens = tokens;
  ec->buffer = sp_buffer;
  fire(ec);
}

Status OpenBSMEventPublisher::run() {
  if (audit_pipe_ == nullptr) {
    return Status(1, "No open audit_pipe");
  }

  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(fileno(audit_pipe_), &fdset);
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 0;
  while (!interrupted()) {
    int rc = select(FD_SETSIZE, &fdset, nullptr, nullptr, &timeout);
    if (rc == 0) {
      break;
    }

    if (rc < 0) {
      if (errno != EINTR) {
        VLOG(1) << "poll() failed with error " << errno;
        return Status::failure("Audit pipe cannot be read");
      }
      break;
    }

    // Data is ready to be dequeued.
    acquireMessages();
  }

  return Status::success();
}

bool OpenBSMEventPublisher::shouldFire(const OpenBSMSubscriptionContextRef& mc,
                                       const OpenBSMEventContextRef& ec) const {
  if (mc->event_id == ec->event_id) {
    return true;
  }
  return false;
}
} // namespace osquery
