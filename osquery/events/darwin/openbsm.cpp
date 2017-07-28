#include <bsm/libbsm.h>

#include <bsm/audit.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "openbsm.h"

namespace osquery {

/// The OpenBSM subsystem may have a performance impact on the system.
FLAG(bool,
     disable_openbsm,
     true,
     "Disable receiving events from the audit subsystem");

REGISTER(OpenBSMEventPublisher, "event_publisher", "openbsm");

Status OpenBSMEventPublisher::setUp() {
  if (FLAGS_disable_openbsm) {
    return Status(1, "Publisher disabled via configuration");
  }
  audit_pipe_ = fopen("/dev/auditpipe", "r");
  if (audit_pipe_ == nullptr) {
    LOG(WARNING) << "The auditpipe couldn't be opened.";
    return Status(1, "Could not open OpenBSM pipe");
  }
  VLOG(1) << "OpenBSM is starting";
  return Status(0);
}
void OpenBSMEventPublisher::configure() {}
void OpenBSMEventPublisher::tearDown() {
  if (audit_pipe_ != nullptr) {
    fclose(audit_pipe_);
  }
}
Status OpenBSMEventPublisher::run() {
  if (audit_pipe_ == nullptr) {
    return Status(1, "No open audit_pipe");
  }
  unsigned char* buffer;
  std::string del = ",";
  tokenstr_t tok;
  auto reclen = 0;
  auto bytesread = 0;
  unsigned int event_id = 0;
  std::vector<tokenstr_t> tokens{};

  while ((reclen = au_read_rec(audit_pipe_, &buffer)) != -1) {
    bytesread = 0;

    while (bytesread < reclen) {
      if (au_fetch_tok(&tok, buffer + bytesread, reclen - bytesread) == -1) {
        break;
      }
      // This can be used to parse the log for us and provided in a
      // delimited list or XML It only writes to file descriptors
      // though. fopenmem()?
      // au_print_flags_tok(stdout, &tok, &del[0], AU_OFLAG_XML);
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
    if (isEnding()) {
      return Status(0);
    }
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