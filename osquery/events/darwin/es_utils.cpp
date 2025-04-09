/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <Kernel/kern/cs_blobs.h>
#include <boost/algorithm/string/join.hpp>
#include <iomanip>
#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/logger/logger.h>
#include <pwd.h>

namespace osquery {

FLAG(bool,
     disable_endpointsecurity,
     true,
     "Disable receiving events from the EndpointSecurity subsystem");

FLAG(bool,
     disable_endpointsecurity_fim,
     true,
     "Disable file events from the EndpointSecurity subsystem");

FLAG(string,
     es_fim_mute_path_literal,
     "",
     "Comma delimited list of path literals to be muted for FIM");

FLAG(string,
     es_fim_mute_path_prefix,
     "",
     "Comma delimited list of path prefixes to be muted for FIM");

// document performance issues
FLAG(bool, es_fim_enable_open_events, false, "Enable open events");

std::string getEsNewClientErrorMessage(const es_new_client_result_t r) {
  switch (r) {
  case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
    return "Internal Error";
  case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
    return "Invalid Argument";
  case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
    return "EndpointSecurity client lacks entitlement";
  case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
    return "EndpointSecurity client lacks user TCC permissions";
  case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
    return "EndpointSecurity client is not running as root";
  case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
    return "Too many EndpointSecurity clients running on the system";
  default:
    return "EndpointSecurity: Unknown Error";
  }
}

std::string getPath(const es_process_t* p) {
  return p->executable->path.length > 0 ? p->executable->path.data : "";
}

std::string getSigningId(const es_process_t* p) {
  return p->signing_id.length > 0 && p->signing_id.data != nullptr
             ? p->signing_id.data
             : "";
}

std::string getCodesigningFlags(const es_process_t* p) {
  // Parses flags from kern/cs_blobs.h header that are useful for monitoring.
  // Flags that are commonly set are inverted to make unusual or potentially
  // insecure processes stand out.

  std::vector<std::string> flags;
  if (!(p->codesigning_flags & CS_VALID)) {
    // Process code signature is invalid, either initially or after paging
    // in an invalid page to a previously valid code signature.
    flags.push_back("NOT_VALID");
  }

  if (p->codesigning_flags & CS_ADHOC) {
    // Process is signed "ad-hoc", without a code signing identity.
    flags.push_back("ADHOC");
  }

  if (!(p->codesigning_flags & CS_RUNTIME)) {
    // Process is signed without using the hardened runtime.
    flags.push_back("NOT_RUNTIME");
  }

  if (p->codesigning_flags & CS_INSTALLER) {
    // Process has installer entitlement, which can modify system integrity
    // protected (SIP) files.
    flags.push_back("INSTALLER");
  }

  return boost::algorithm::join(flags, ", ");
}

std::string getTeamId(const es_process_t* p) {
  return p->team_id.length > 0 && p->team_id.data != nullptr ? p->team_id.data
                                                             : "";
}

std::string getStringFromToken(es_string_token_t* t) {
  return t->length > 0 && t->data != nullptr ? t->data : "";
}

std::string getStringFromToken(const es_string_token_t* t) {
  return t->length > 0 && t->data != nullptr ? t->data : "";
}

std::string getCwdPathFromPid(pid_t pid) {
  struct proc_vnodepathinfo vpi {};
  auto bytes = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof(vpi));
  return bytes <= 0 ? "" : vpi.pvi_cdir.vip_path;
}

std::string getCDHash(const es_process_t* p) {
  std::stringstream hash;
  for (unsigned char i : p->cdhash) {
    hash << std::hex << std::setfill('0') << std::setw(2)
         << static_cast<unsigned int>(i);
  }
  auto s = hash.str();
  return s.find_first_not_of(s.front()) == std::string::npos ? "" : s;
}

void getProcessProperties(const es_process_t* p,
                          const EndpointSecurityEventContextRef& ec) {
  auto audit_token = p->audit_token;
  ec->pid = audit_token_to_pid(audit_token);
  ec->pidversion = audit_token_to_pidversion(p->audit_token);
  ec->parent = p->ppid;
  ec->parent_pidversion = audit_token_to_pidversion(p->parent_audit_token);
  ec->original_parent = p->original_ppid;
  ec->session_id = p->session_id;
  ec->responsible_pid = audit_token_to_pid(p->responsible_audit_token);
  ec->responsible_pidversion =
      audit_token_to_pidversion(p->responsible_audit_token);

  ec->path = getPath(p);
  ec->cwd = getCwdPathFromPid(ec->pid);

  ec->uid = audit_token_to_ruid(audit_token);
  ec->euid = audit_token_to_egid(audit_token);
  ec->gid = audit_token_to_rgid(audit_token);
  ec->egid = audit_token_to_egid(audit_token);

  ec->signing_id = getSigningId(p);
  ec->team_id = getTeamId(p);
  ec->cdhash = getCDHash(p);
  ec->platform_binary = p->is_platform_binary;
  ec->codesigning_flags = getCodesigningFlags(p);

  auto user = getpwuid(ec->uid);
  ec->username = user->pw_name != nullptr ? std::string(user->pw_name) : "";

  ec->cwd = getCwdPathFromPid(ec->pid);
}

void appendQuotedString(std::ostream& out, std::string s, char delim) {
  if (s.find(delim) != std::string::npos || s.find('"') != std::string::npos) {
    out << std::quoted(s) << delim;
  } else {
    out << s << delim;
  }
}

} // namespace osquery
