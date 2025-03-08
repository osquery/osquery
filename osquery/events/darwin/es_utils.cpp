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
#include <boost/algorithm/string/split.hpp>
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

// Enable comprehensive EndpointSecurity events subscription options
FLAG(bool,
     enable_es_network_events,
     false,
     "Enable network-related events from EndpointSecurity");

FLAG(bool,
     enable_es_auth_events,
     false,
     "Enable authorization-related events from EndpointSecurity");

FLAG(bool,
     enable_es_file_events,
     false,
     "Enable file-related events from EndpointSecurity");

FLAG(bool,
     enable_es_plist_events,
     false,
     "Enable plist-related events from EndpointSecurity");

FLAG(bool,
     enable_es_remote_thread_events,
     false,
     "Enable remote thread events from EndpointSecurity");

FLAG(bool,
     enable_es_screensharing_events,
     false,
     "Enable screen sharing events from EndpointSecurity");

FLAG(bool,
     enable_es_profile_events,
     false,
     "Enable profile-related events from EndpointSecurity");

FLAG(bool,
     enable_es_authentication_events,
     false,
     "Enable authentication-related events from EndpointSecurity");

FLAG(bool,
     enable_es_xpc_events,
     false,
     "Enable XPC-related events from EndpointSecurity");

FLAG(bool,
     enable_es_memory_events,
     false,
     "Enable memory protection events from EndpointSecurity (mmap, mprotect)");

FLAG(bool,
     enable_es_system_events,
     false,
     "Enable kernel extension and system control events from EndpointSecurity");

FLAG(string,
     es_enabled_events,
     "",
     "Comma-delimited list of specific EndpointSecurity event types to enable "
     "(e.g., 'notify_mount,notify_unmount,notify_setuid')");

std::map<std::string, es_event_type_t> kESEventNameMap = {
    // Base macOS 10.15 events
    {"notify_exec", ES_EVENT_TYPE_NOTIFY_EXEC},
    {"notify_fork", ES_EVENT_TYPE_NOTIFY_FORK},
    {"notify_exit", ES_EVENT_TYPE_NOTIFY_EXIT},
    {"notify_close", ES_EVENT_TYPE_NOTIFY_CLOSE},
    {"notify_create", ES_EVENT_TYPE_NOTIFY_CREATE},
    {"notify_exchangedata", ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA},
    {"notify_link", ES_EVENT_TYPE_NOTIFY_LINK},
    {"notify_mount", ES_EVENT_TYPE_NOTIFY_MOUNT},
    {"notify_open", ES_EVENT_TYPE_NOTIFY_OPEN},
    {"notify_rename", ES_EVENT_TYPE_NOTIFY_RENAME},
    {"notify_setattrlist", ES_EVENT_TYPE_NOTIFY_SETATTRLIST},
    {"notify_setextattr", ES_EVENT_TYPE_NOTIFY_SETEXTATTR},
    {"notify_setflags", ES_EVENT_TYPE_NOTIFY_SETFLAGS},
    {"notify_setmode", ES_EVENT_TYPE_NOTIFY_SETMODE},
    {"notify_setowner", ES_EVENT_TYPE_NOTIFY_SETOWNER},
    {"notify_signal", ES_EVENT_TYPE_NOTIFY_SIGNAL},
    {"notify_truncate", ES_EVENT_TYPE_NOTIFY_TRUNCATE},
    {"notify_unlink", ES_EVENT_TYPE_NOTIFY_UNLINK},
    {"notify_unmount", ES_EVENT_TYPE_NOTIFY_UNMOUNT},
    {"notify_write", ES_EVENT_TYPE_NOTIFY_WRITE},
    {"notify_access", ES_EVENT_TYPE_NOTIFY_ACCESS},
    {"notify_chdir", ES_EVENT_TYPE_NOTIFY_CHDIR},
    {"notify_chroot", ES_EVENT_TYPE_NOTIFY_CHROOT},
    {"notify_clone", ES_EVENT_TYPE_NOTIFY_CLONE},
    {"notify_copyfile", ES_EVENT_TYPE_NOTIFY_COPYFILE},
    {"notify_deleteextattr", ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR},
    {"notify_dup", ES_EVENT_TYPE_NOTIFY_DUP},
    {"notify_fcntl", ES_EVENT_TYPE_NOTIFY_FCNTL},
    {"notify_fsgetpath", ES_EVENT_TYPE_NOTIFY_FSGETPATH},
    {"notify_get_task", ES_EVENT_TYPE_NOTIFY_GET_TASK},
    {"notify_getattrlist", ES_EVENT_TYPE_NOTIFY_GETATTRLIST},
    {"notify_getextattr", ES_EVENT_TYPE_NOTIFY_GETEXTATTR},
    {"notify_iokit_open", ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN},
    {"notify_kextload", ES_EVENT_TYPE_NOTIFY_KEXTLOAD},
    {"notify_kextunload", ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD},
    {"notify_listextattr", ES_EVENT_TYPE_NOTIFY_LISTEXTATTR},
    {"notify_lookup", ES_EVENT_TYPE_NOTIFY_LOOKUP},
    {"notify_mmap", ES_EVENT_TYPE_NOTIFY_MMAP},
    {"notify_proc_check", ES_EVENT_TYPE_NOTIFY_PROC_CHECK},
    {"notify_proc_suspend_resume", ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME},
    {"notify_readdir", ES_EVENT_TYPE_NOTIFY_READDIR},
    {"notify_readlink", ES_EVENT_TYPE_NOTIFY_READLINK},
    {"notify_settime", ES_EVENT_TYPE_NOTIFY_SETTIME},
    {"notify_uipc_bind", ES_EVENT_TYPE_NOTIFY_UIPC_BIND},
    {"notify_uipc_connect", ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT},
    {"notify_utimes", ES_EVENT_TYPE_NOTIFY_UTIMES},

    // macOS 10.15.4+
    {"notify_pty_grant", ES_EVENT_TYPE_NOTIFY_PTY_GRANT},
    {"notify_pty_close", ES_EVENT_TYPE_NOTIFY_PTY_CLOSE},

    // macOS 11.0+
    {"notify_cs_invalidated", ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED},
    {"notify_setacl", ES_EVENT_TYPE_NOTIFY_SETACL},
    {"notify_readdir_extended", ES_EVENT_TYPE_NOTIFY_READDIR_EXTENDED},
    {"notify_searchfs", ES_EVENT_TYPE_NOTIFY_SEARCHFS},

    // macOS 11.3+
    {"notify_remote_thread_create", ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE},

    // macOS 12.0+
    {"notify_setuid", ES_EVENT_TYPE_NOTIFY_SETUID},
    {"notify_seteuid", ES_EVENT_TYPE_NOTIFY_SETEUID},
    {"notify_setreuid", ES_EVENT_TYPE_NOTIFY_SETREUID},
    {"notify_setegid", ES_EVENT_TYPE_NOTIFY_SETEGID},
    {"notify_setregid", ES_EVENT_TYPE_NOTIFY_SETREGID},

    // macOS 13.0+
    {"notify_authentication", ES_EVENT_TYPE_NOTIFY_AUTHENTICATION},
    {"notify_xp_malware_detected", ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED},
    {"notify_xp_malware_remediated",
     ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED},
    {"notify_sysctl", ES_EVENT_TYPE_NOTIFY_SYSCTL},
    {"notify_openssh_login", ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN},
    {"notify_openssh_logout", ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT},
    {"notify_screensharing_event", ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH},
    {"notify_screensharing_attach", ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH},
    {"notify_screensharing_detach", ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH},

    // macOS 14.0+
    {"notify_profile_add", ES_EVENT_TYPE_NOTIFY_PROFILE_ADD},
    {"notify_profile_remove", ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE},
    {"notify_su", ES_EVENT_TYPE_NOTIFY_SU},
    {"notify_authorization", ES_EVENT_TYPE_NOTIFY_AUTHORIZATION},
    {"notify_authorization_petition",
     ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION},
    {"notify_authorization_judgement",
     ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT},
    {"notify_sudo", ES_EVENT_TYPE_NOTIFY_SUDO},
    {"notify_od_group_add", ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD},
    {"notify_od_group_remove", ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE},
    {"notify_od_group_set", ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET},
    {"notify_od_modify_password", ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD},
    {"notify_xpc_connect", ES_EVENT_TYPE_NOTIFY_XPC_CONNECT}};

std::vector<es_event_type_t> getEnabledEventTypes() {
  std::vector<es_event_type_t> events;

  // Always include base process events
  events.push_back(ES_EVENT_TYPE_NOTIFY_EXEC);
  events.push_back(ES_EVENT_TYPE_NOTIFY_FORK);
  events.push_back(ES_EVENT_TYPE_NOTIFY_EXIT);

  // Include file-related events based on FIM setting
  if (!FLAGS_disable_endpointsecurity_fim) {
    events.push_back(ES_EVENT_TYPE_NOTIFY_CREATE);
    events.push_back(ES_EVENT_TYPE_NOTIFY_RENAME);
    events.push_back(ES_EVENT_TYPE_NOTIFY_WRITE);
    events.push_back(ES_EVENT_TYPE_NOTIFY_TRUNCATE);

    if (FLAGS_es_fim_enable_open_events) {
      events.push_back(ES_EVENT_TYPE_NOTIFY_OPEN);
    }
  }

  // Add network-related events
  if (FLAGS_enable_es_network_events) {
    events.push_back(ES_EVENT_TYPE_NOTIFY_SOCKET);
    events.push_back(ES_EVENT_TYPE_NOTIFY_CONNECT);
    events.push_back(ES_EVENT_TYPE_NOTIFY_BIND);
    events.push_back(ES_EVENT_TYPE_NOTIFY_LISTEN);
    events.push_back(ES_EVENT_TYPE_NOTIFY_ACCEPT);
    events.push_back(ES_EVENT_TYPE_NOTIFY_UIPC_BIND);
    events.push_back(ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT);
  }

  // Add auth-related events
  if (FLAGS_enable_es_auth_events) {
    events.push_back(ES_EVENT_TYPE_NOTIFY_SETUID);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SETEUID);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SETREUID);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SETEGID);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SETREGID);
  }

  // Add file system-related events
  if (FLAGS_enable_es_file_events) {
    // Basic file operations
    events.push_back(ES_EVENT_TYPE_NOTIFY_CLOSE);
    events.push_back(ES_EVENT_TYPE_NOTIFY_UNLINK);
    events.push_back(ES_EVENT_TYPE_NOTIFY_ACCESS);
    events.push_back(ES_EVENT_TYPE_NOTIFY_LOOKUP);
    events.push_back(ES_EVENT_TYPE_NOTIFY_READDIR);
    events.push_back(ES_EVENT_TYPE_NOTIFY_READDIR_EXTENDED);
    events.push_back(ES_EVENT_TYPE_NOTIFY_READLINK);
    events.push_back(ES_EVENT_TYPE_NOTIFY_FSGETPATH);
    events.push_back(ES_EVENT_TYPE_NOTIFY_CHDIR);
    events.push_back(ES_EVENT_TYPE_NOTIFY_CHROOT);
    events.push_back(ES_EVENT_TYPE_NOTIFY_MOUNT);
    events.push_back(ES_EVENT_TYPE_NOTIFY_UNMOUNT);

    // Advanced file operations - data exchange
    events.push_back(ES_EVENT_TYPE_NOTIFY_LINK);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SYMLINK);
    events.push_back(ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA);
    events.push_back(ES_EVENT_TYPE_NOTIFY_CLONE);
    events.push_back(ES_EVENT_TYPE_NOTIFY_COPYFILE);

    // Advanced file operations - permissions
    events.push_back(ES_EVENT_TYPE_NOTIFY_SETMODE);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SETOWNER);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SETACL);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SETFLAGS);
    events.push_back(ES_EVENT_TYPE_NOTIFY_CHMOD);
    events.push_back(ES_EVENT_TYPE_NOTIFY_CHOWN);

    // Advanced file operations - metadata
    events.push_back(ES_EVENT_TYPE_NOTIFY_SETATTRLIST);
    events.push_back(ES_EVENT_TYPE_NOTIFY_GETATTRLIST);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SEARCHFS);

    // Advanced file operations - extended attributes
    events.push_back(ES_EVENT_TYPE_NOTIFY_SETEXTATTR);
    events.push_back(ES_EVENT_TYPE_NOTIFY_GETEXTATTR);
    events.push_back(ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR);
    events.push_back(ES_EVENT_TYPE_NOTIFY_LISTEXTATTR);
  }

  // Add remote thread events
  if (FLAGS_enable_es_remote_thread_events) {
    events.push_back(ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE);
  }

  // Add screensharing events
  if (FLAGS_enable_es_screensharing_events) {
    events.push_back(ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH);
  }

  // Add profile events
  if (FLAGS_enable_es_profile_events) {
    events.push_back(ES_EVENT_TYPE_NOTIFY_PROFILE_ADD);
    events.push_back(ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE);
  }

  // Add authentication events
  if (FLAGS_enable_es_authentication_events) {
    events.push_back(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION);
    events.push_back(ES_EVENT_TYPE_NOTIFY_AUTHORIZATION);
    events.push_back(ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION);
    events.push_back(ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SU);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SUDO);
    events.push_back(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN);
    events.push_back(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT);
  }

  // Add XPC events
  if (FLAGS_enable_es_xpc_events) {
    events.push_back(ES_EVENT_TYPE_NOTIFY_XPC_CONNECT);
  }

  // Add memory protection events
  if (FLAGS_enable_es_memory_events) {
    events.push_back(ES_EVENT_TYPE_NOTIFY_MMAP);
    events.push_back(ES_EVENT_TYPE_NOTIFY_MPROTECT);
  }

  // Add kernel and system events
  if (FLAGS_enable_es_system_events) {
    events.push_back(ES_EVENT_TYPE_NOTIFY_KEXTLOAD);
    events.push_back(ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD);
    events.push_back(ES_EVENT_TYPE_NOTIFY_SYSCTL);
  }

  // Add specifically enabled events from the es_enabled_events list
  if (!FLAGS_es_enabled_events.empty()) {
    std::vector<std::string> event_names;
    boost::split(event_names, FLAGS_es_enabled_events, boost::is_any_of(","));

    for (const auto& name : event_names) {
      auto it = kESEventNameMap.find(name);
      if (it != kESEventNameMap.end()) {
        // Check if the event is already in the list
        if (std::find(events.begin(), events.end(), it->second) ==
            events.end()) {
          events.push_back(it->second);
        }
      } else {
        VLOG(1) << "Unknown EndpointSecurity event type: " << name;
      }
    }
  }

  return events;
}

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

std::string getSocketDomainDescription(int domain) {
  switch (domain) {
  case AF_INET:
    return "IPv4";
  case AF_INET6:
    return "IPv6";
  case AF_UNIX:
    return "Unix Domain Socket";
  case AF_LOCAL:
    return "Local";
  case AF_SYSTEM:
    return "System";
  case PF_NDRV:
    return "Network Driver";
  case AF_ROUTE:
    return "Routing";
  case AF_LINK:
    return "Link Layer";
  case AF_BLUETOOTH:
    return "Bluetooth";
  default:
    return "Unknown Domain (" + std::to_string(domain) + ")";
  }
}

std::string getSocketTypeDescription(int type) {
  switch (type) {
  case SOCK_STREAM:
    return "Stream";
  case SOCK_DGRAM:
    return "Datagram";
  case SOCK_RAW:
    return "Raw";
  case SOCK_SEQPACKET:
    return "Sequential Packet";
  default:
    return "Unknown Type (" + std::to_string(type) + ")";
  }
}

std::string getSocketProtocolDescription(int protocol) {
  switch (protocol) {
  case IPPROTO_TCP:
    return "TCP";
  case IPPROTO_UDP:
    return "UDP";
  case IPPROTO_ICMP:
    return "ICMP";
  case IPPROTO_RAW:
    return "Raw IP";
  case IPPROTO_IP:
    return "Default IP";
  case IPPROTO_SCTP:
    return "SCTP";
  case 0:
    return "Default";
  default:
    return "Unknown Protocol (" + std::to_string(protocol) + ")";
  }
}

std::string getEventCategoryString(es_event_type_t event_type) {
  if (__builtin_available(macos 10.15, *)) {
    if (event_type == ES_EVENT_TYPE_NOTIFY_EXEC ||
        event_type == ES_EVENT_TYPE_NOTIFY_FORK ||
        event_type == ES_EVENT_TYPE_NOTIFY_EXIT) {
      return "process";
    } else if (event_type == ES_EVENT_TYPE_NOTIFY_AUTHENTICATION ||
               event_type == ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED ||
               event_type == ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED ||
               event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN ||
               event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT ||
               event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK ||
               event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK ||
               event_type == ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN ||
               event_type == ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT ||
               event_type == ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN ||
               event_type == ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT ||
               event_type == ES_EVENT_TYPE_NOTIFY_SU ||
               event_type == ES_EVENT_TYPE_NOTIFY_SUDO ||
               event_type == ES_EVENT_TYPE_NOTIFY_AUTHORIZATION) {
      return "authentication";
    } else if (event_type == ES_EVENT_TYPE_NOTIFY_SOCKET ||
               event_type == ES_EVENT_TYPE_NOTIFY_CONNECT ||
               event_type == ES_EVENT_TYPE_NOTIFY_BIND ||
               event_type == ES_EVENT_TYPE_NOTIFY_LISTEN ||
               event_type == ES_EVENT_TYPE_NOTIFY_ACCEPT ||
               event_type == ES_EVENT_TYPE_NOTIFY_UIPC_BIND ||
               event_type == ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT) {
      return "network";
    } else if (event_type == ES_EVENT_TYPE_NOTIFY_CREATE ||
               event_type == ES_EVENT_TYPE_NOTIFY_OPEN ||
               event_type == ES_EVENT_TYPE_NOTIFY_CLOSE ||
               event_type == ES_EVENT_TYPE_NOTIFY_RENAME ||
               event_type == ES_EVENT_TYPE_NOTIFY_UNLINK ||
               event_type == ES_EVENT_TYPE_NOTIFY_WRITE ||
               event_type == ES_EVENT_TYPE_NOTIFY_TRUNCATE ||
               event_type == ES_EVENT_TYPE_NOTIFY_READDIR) {
      return "filesystem";
    } else if (event_type == ES_EVENT_TYPE_NOTIFY_SETUID ||
               event_type == ES_EVENT_TYPE_NOTIFY_SETGID ||
               event_type == ES_EVENT_TYPE_NOTIFY_SETEUID ||
               event_type == ES_EVENT_TYPE_NOTIFY_SETEGID ||
               event_type == ES_EVENT_TYPE_NOTIFY_SETREUID ||
               event_type == ES_EVENT_TYPE_NOTIFY_SETREGID) {
      return "privilege";
    } else if (event_type == ES_EVENT_TYPE_NOTIFY_MOUNT ||
               event_type == ES_EVENT_TYPE_NOTIFY_UNMOUNT ||
               event_type == ES_EVENT_TYPE_NOTIFY_KEXTLOAD ||
               event_type == ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD) {
      return "system";
    } else if (event_type == ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE) {
      return "remote";
    } else if (event_type == ES_EVENT_TYPE_NOTIFY_PROFILE_ADD ||
               event_type == ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE) {
      return "profile";
    } else if (event_type == ES_EVENT_TYPE_NOTIFY_XPC_CONNECT) {
      return "xpc";
    }
  }
  return "unknown";
}

std::string getEventSeverityString(es_event_type_t event_type) {
  if (__builtin_available(macos 10.15, *)) {
    // High severity events
    if (event_type == ES_EVENT_TYPE_NOTIFY_EXEC ||
        event_type == ES_EVENT_TYPE_NOTIFY_AUTHENTICATION ||
        event_type == ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED ||
        event_type == ES_EVENT_TYPE_NOTIFY_KEXTLOAD ||
        event_type == ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD ||
        event_type == ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE ||
        event_type == ES_EVENT_TYPE_NOTIFY_SETUID ||
        event_type == ES_EVENT_TYPE_NOTIFY_SETEUID ||
        event_type == ES_EVENT_TYPE_NOTIFY_SETREUID ||
        event_type == ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN ||
        event_type == ES_EVENT_TYPE_NOTIFY_SU ||
        event_type == ES_EVENT_TYPE_NOTIFY_SUDO) {
      return "high";
    }
    // Medium severity events
    else if (event_type == ES_EVENT_TYPE_NOTIFY_FORK ||
             event_type == ES_EVENT_TYPE_NOTIFY_UNLINK ||
             event_type == ES_EVENT_TYPE_NOTIFY_WRITE ||
             event_type == ES_EVENT_TYPE_NOTIFY_RENAME ||
             event_type == ES_EVENT_TYPE_NOTIFY_TRUNCATE ||
             event_type == ES_EVENT_TYPE_NOTIFY_CONNECT ||
             event_type == ES_EVENT_TYPE_NOTIFY_BIND ||
             event_type == ES_EVENT_TYPE_NOTIFY_LISTEN ||
             event_type == ES_EVENT_TYPE_NOTIFY_ACCEPT ||
             event_type == ES_EVENT_TYPE_NOTIFY_SETGID ||
             event_type == ES_EVENT_TYPE_NOTIFY_SETEGID ||
             event_type == ES_EVENT_TYPE_NOTIFY_SETREGID ||
             event_type == ES_EVENT_TYPE_NOTIFY_MOUNT ||
             event_type == ES_EVENT_TYPE_NOTIFY_UNMOUNT) {
      return "medium";
    }
  }
  // Default to low severity for all other events
  return "low";
}

std::string getEventDescription(
    const std::string& event_name,
    const std::map<std::string, std::string>& metadata) {
  if (event_name == "exec") {
    return "Process execution";
  } else if (event_name == "fork") {
    return "Process fork";
  } else if (event_name == "exit") {
    return "Process exit";
  } else if (event_name == "socket") {
    return "Socket creation";
  } else if (event_name == "connect") {
    std::string description = "Network connection";
    if (metadata.count("domain_description") > 0 &&
        metadata.count("protocol_description") > 0) {
      description += " (" + metadata.at("domain_description") + " " +
                     metadata.at("protocol_description") + ")";
    }
    return description;
  } else if (event_name == "bind") {
    std::string description = "Socket binding";
    if (metadata.count("domain_description") > 0) {
      description += " (" + metadata.at("domain_description") + ")";
    }
    return description;
  } else if (event_name == "listen") {
    return "Socket listening for connections";
  } else if (event_name == "accept") {
    return "Connection acceptance";
  } else if (event_name == "setuid" || event_name == "seteuid" ||
             event_name == "setreuid") {
    return "User ID change";
  } else if (event_name == "setgid" || event_name == "setegid" ||
             event_name == "setregid") {
    return "Group ID change";
  } else if (event_name == "mount") {
    return "Filesystem mount";
  } else if (event_name == "unmount") {
    return "Filesystem unmount";
  } else if (event_name == "openssh_login") {
    return "SSH login";
  } else if (event_name == "openssh_logout") {
    return "SSH logout";
  } else if (event_name == "screensharing_attach") {
    return "Screen sharing connection";
  } else if (event_name == "screensharing_detach") {
    return "Screen sharing disconnection";
  } else if (event_name == "remote_thread_create") {
    return "Remote thread creation";
  } else if (event_name == "create") {
    return "File creation";
  } else if (event_name == "write") {
    return "File modification";
  } else if (event_name == "rename") {
    return "File renamed";
  } else if (event_name == "unlink") {
    return "File deletion";
  } else if (event_name == "authentication") {
    return "Authentication event";
  } else if (event_name == "su") {
    return "SU command execution";
  } else if (event_name == "sudo") {
    return "Sudo command execution";
  } else if (event_name == "xpc_connect") {
    std::string description = "XPC service connection";
    if (metadata.count("service_name") > 0) {
      description += " to " + metadata.at("service_name");
    }
    return description;
  }

  // Default for other events
  return "EndpointSecurity event: " + event_name;
}

} // namespace osquery
