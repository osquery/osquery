/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <bsm/libbsm.h>
#include <security/audit/audit_ioctl.h>
#include <sys/ioctl.h>
#include <sys/select.h>

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

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
  WriteLock lock(audit_pipe_mutex_);

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
  std::set<std::string> ev_classes;

  if (true == FLAGS_audit_allow_process_events) {
    // capture process events
    ev_classes.insert("pc");
  }

  if (true == FLAGS_audit_allow_sockets) {
    // capture network events
    ev_classes.insert("nt");
  }

  if (true == FLAGS_audit_allow_user_events) {
    // capture user (login, authorization, etc.) events
    ev_classes.insert("lo");
    ev_classes.insert("aa");
  }

  if (true == FLAGS_audit_allow_fim_events) {
    // capture file events
    ev_classes.insert("fc");
    ev_classes.insert("fd");
    ev_classes.insert("fw");
    ev_classes.insert("fr");
    ev_classes.insert("fa");
    ev_classes.insert("fm");
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
    return Status::failure("Could not open auditpipe");
  }

  return FLAGS_audit_allow_config ? configureAuditPipe() : Status::success();
}

void OpenBSMEventPublisher::configure() {
  std::set<size_t> event_ids;
  for (const auto& sub : subscriptions_) {
    auto sc = getSubscriptionContext(sub->context);
    event_ids.insert(sc->event_id);
  }

  WriteLock lock(event_ids_mutex_);
  event_ids_ = std::move(event_ids);
}

void OpenBSMEventPublisher::tearDown() {
  WriteLock lock(audit_pipe_mutex_);

  if (audit_pipe_ != nullptr) {
    fclose(audit_pipe_);
    audit_pipe_ = nullptr;
  }
}

void OpenBSMEventPublisher::acquireMessages() {
  auto buffer = static_cast<unsigned char*>(nullptr);
  int reclen = 0;

  {
    ReadLock lock(audit_pipe_mutex_);
    reclen = au_read_rec(audit_pipe_, &buffer);
  }

  if (reclen <= 0) {
    return;
  }

  // We'll use these to dequeue below.
  tokenstr_t tok;
  std::vector<tokenstr_t> tokens{};
  // Predict that we usually use 6-12 tokens.
  tokens.reserve(12);

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
  {
    ReadLock lock(event_ids_mutex_);
    if (event_ids_.find(event_id) == event_ids_.end()) {
      // Return early to avoid parsing / checking loud and unused event IDs.
      return;
    }
  }

  auto ec = createEventContext();
  ec->event_id = event_id;
  ec->tokens = std::move(tokens);
  ec->tokens.shrink_to_fit();
  ec->buffer = sp_buffer;
  fire(ec);
}

Status OpenBSMEventPublisher::run() {
  {
    ReadLock lock(audit_pipe_mutex_);
    if (audit_pipe_ == nullptr) {
      return Status::failure("Auditpipe is not open");
    }
  }

  int rc = 0;
  fd_set fdset;
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 200000;

  while (!isEnding()) {
    {
      ReadLock lock(audit_pipe_mutex_);

      FD_ZERO(&fdset);
      FD_SET(fileno(audit_pipe_), &fdset);

      rc = select(FD_SETSIZE, &fdset, nullptr, nullptr, &timeout);
    }

    if (isEnding()) {
      // Events ended while waiting, ignore any data ready to be read.
      break;
    }
    if (rc == 0) {
      continue;
    }

    if (rc < 0) {
      if (errno != EINTR) {
        VLOG(1) << "poll() failed with error " << errno;
        return Status::failure("Auditpipe cannot be read");
      }
      continue;
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
