/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/darwin/es_utils.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

DECLARE_bool(disable_endpointsecurity);

REGISTER(EndpointSecurityPublisher, "event_publisher", "endpointsecurity")

Status EndpointSecurityPublisher::setUp() {
  if (__builtin_available(macos 10.15, *)) {
    if (FLAGS_disable_endpointsecurity) {
      return Status::failure(1,
                             "EndpointSecurity is disabled via configuration");
    }

    auto handler = ^(es_client_t* client, const es_message_t* message) {
      handleMessage(message);
    };

    auto result = es_new_client(&es_client_, handler);

    if (result == ES_NEW_CLIENT_RESULT_SUCCESS) {
      es_client_success_ = true;
      return Status::success();
    } else {
      return Status::failure(1, getEsNewClientErrorMessage(result));
    }
  } else {
    return Status::failure(
        1, "EndpointSecurity is only available on macOS 10.15 and higher");
  }
}

void EndpointSecurityPublisher::configure() {
  if (es_client_ == nullptr) {
    return;
  }

  auto cache = es_clear_cache(es_client_);
  if (cache != ES_CLEAR_CACHE_RESULT_SUCCESS) {
    VLOG(1) << "Couldn't clear cache for EndpointSecurity client";
    return;
  }

  std::vector<es_event_type_t> event_types;
  for (auto& sub : subscriptions_) {
    auto sc = getSubscriptionContext(sub->context);
    auto events = sc->es_event_subscriptions_;
    // Add all event types from this subscription
    event_types.insert(event_types.end(), events.begin(), events.end());
  }

  // Remove duplicate event types
  std::sort(event_types.begin(), event_types.end());
  event_types.erase(std::unique(event_types.begin(), event_types.end()),
                    event_types.end());

  if (!event_types.empty()) {
    auto es_sub = es_subscribe(es_client_, &event_types[0], event_types.size());
    if (es_sub != ES_RETURN_SUCCESS) {
      VLOG(1) << "Couldn't subscribe to EndpointSecurity subsystem";
    } else {
      VLOG(1) << "Successfully subscribed to " << event_types.size()
              << " EndpointSecurity event types";
    }
  }
}

void EndpointSecurityPublisher::tearDown() {
  if (es_client_ == nullptr) {
    return;
  }
  es_unsubscribe_all(es_client_);

  if (es_client_success_) {
    auto result = es_delete_client(es_client_);
    if (result != ES_RETURN_SUCCESS) {
      VLOG(1) << "endpointsecurity: error tearing down es_client";
    }
    es_client_ = nullptr;
  }
}

void EndpointSecurityPublisher::handleMessage(const es_message_t* message) {
  if (message == nullptr) {
    return;
  }

  // Only handle NOTIFY events here, not AUTH
  if (message->action_type == ES_ACTION_TYPE_AUTH) {
    return;
  }

  auto ec = createEventContext();

  ec->version = message->version;
  if (ec->version >= 2) {
    ec->seq_num = message->seq_num;
  }

  if (ec->version >= 4) {
    ec->global_seq_num = message->global_seq_num;
  }

  getProcessProperties(message->process, ec);
  ec->es_event = message->event_type;

  switch (message->event_type) {
  // Process lifecycle events
  case ES_EVENT_TYPE_NOTIFY_EXEC: {
    ec->event_type = "exec";

    getProcessProperties(message->event.exec.target, ec);
    ec->argc = es_exec_arg_count(&message->event.exec);
    {
      std::stringstream args;
      for (auto i = 0; i < ec->argc; i++) {
        auto arg = es_exec_arg(&message->event.exec, i);
        auto s = getStringFromToken(&arg);
        appendQuotedString(args, s, ' ');
      }
      ec->args = args.str();
    }

    ec->envc = es_exec_env_count(&message->event.exec);
    {
      std::stringstream envs;
      for (auto i = 0; i < ec->envc; i++) {
        auto env = es_exec_env(&message->event.exec, i);
        auto s = getStringFromToken(&env);
        appendQuotedString(envs, s, ' ');
      }
      ec->envs = envs.str();
    }

    if (ec->version >= 3) {
      ec->cwd = getStringFromToken(&message->event.exec.cwd->path);
    }
  } break;
  case ES_EVENT_TYPE_NOTIFY_FORK: {
    ec->event_type = "fork";
    ec->child_pid = audit_token_to_pid(message->event.fork.child->audit_token);
  } break;
  case ES_EVENT_TYPE_NOTIFY_EXIT: {
    ec->event_type = "exit";
    ec->exit_code = message->event.exit.stat;
  } break;

  // Signal events
  case ES_EVENT_TYPE_NOTIFY_SIGNAL: {
    ec->event_type = "signal";
    ec->signal_number = message->event.signal.sig;
    if (message->event.signal.target) {
      ec->metadata["target_pid"] = std::to_string(
          audit_token_to_pid(message->event.signal.target->audit_token));
    }
  } break;

  // UID/GID events
  case ES_EVENT_TYPE_NOTIFY_SETUID: {
    ec->event_type = "setuid";
    ec->target_uid = message->event.setuid.uid;
  } break;
  case ES_EVENT_TYPE_NOTIFY_SETEUID: {
    ec->event_type = "seteuid";
    ec->target_uid = message->event.seteuid.uid;
  } break;
  case ES_EVENT_TYPE_NOTIFY_SETREUID: {
    ec->event_type = "setreuid";
    ec->target_uid = message->event.setreuid.ruid;
    ec->target_euid = message->event.setreuid.euid;
  } break;
  case ES_EVENT_TYPE_NOTIFY_SETEGID: {
    ec->event_type = "setegid";
    ec->target_gid = message->event.setegid.gid;
  } break;
  case ES_EVENT_TYPE_NOTIFY_SETREGID: {
    ec->event_type = "setregid";
    ec->target_gid = message->event.setregid.rgid;
    ec->target_egid = message->event.setregid.egid;
  } break;

  // Network events
  case ES_EVENT_TYPE_NOTIFY_SOCKET: {
    ec->event_type = "socket";
    ec->socket_domain = std::to_string(message->event.socket.domain);
    ec->socket_type = std::to_string(message->event.socket.type);
    ec->socket_protocol = std::to_string(message->event.socket.protocol);
    // Map domain, type, and protocol to human-readable values for better
    // usability
    ec->metadata["domain_description"] =
        getSocketDomainDescription(message->event.socket.domain);
    ec->metadata["type_description"] =
        getSocketTypeDescription(message->event.socket.type);
    ec->metadata["protocol_description"] =
        getSocketProtocolDescription(message->event.socket.protocol);
  } break;
  case ES_EVENT_TYPE_NOTIFY_CONNECT: {
    ec->event_type = "connect";
    // Extract socket information
    ec->socket_domain = std::to_string(message->event.connect.socket_domain);
    ec->socket_type = std::to_string(message->event.connect.socket_type);
    ec->socket_protocol =
        std::to_string(message->event.connect.socket_protocol);

    // Map domain, type, and protocol to human-readable values
    ec->metadata["domain_description"] =
        getSocketDomainDescription(message->event.connect.socket_domain);
    ec->metadata["type_description"] =
        getSocketTypeDescription(message->event.connect.socket_type);
    ec->metadata["protocol_description"] =
        getSocketProtocolDescription(message->event.connect.socket_protocol);

    // Extract remote endpoint information based on the address family
    if (message->event.connect.socket_domain == AF_INET) {
      // IPv4 address handling
      if (message->event.connect.remote_address) {
        char addr_str[INET_ADDRSTRLEN] = {0};
        const struct sockaddr_in* addr =
            (const struct sockaddr_in*)message->event.connect.remote_address;
        inet_ntop(AF_INET, &(addr->sin_addr), addr_str, INET_ADDRSTRLEN);
        ec->remote_address = addr_str;
        ec->remote_port = ntohs(addr->sin_port);
      }
    } else if (message->event.connect.socket_domain == AF_INET6) {
      // IPv6 address handling
      if (message->event.connect.remote_address) {
        char addr_str[INET6_ADDRSTRLEN] = {0};
        const struct sockaddr_in6* addr =
            (const struct sockaddr_in6*)message->event.connect.remote_address;
        inet_ntop(AF_INET6, &(addr->sin6_addr), addr_str, INET6_ADDRSTRLEN);
        ec->remote_address = addr_str;
        ec->remote_port = ntohs(addr->sin6_port);
      }
    }
  } break;
  case ES_EVENT_TYPE_NOTIFY_BIND: {
    ec->event_type = "bind";
    // Extract socket information
    ec->socket_domain = std::to_string(message->event.bind.socket_domain);
    ec->socket_type = std::to_string(message->event.bind.socket_type);
    ec->socket_protocol = std::to_string(message->event.bind.socket_protocol);

    // Map domain, type, and protocol to human-readable values
    ec->metadata["domain_description"] =
        getSocketDomainDescription(message->event.bind.socket_domain);
    ec->metadata["type_description"] =
        getSocketTypeDescription(message->event.bind.socket_type);
    ec->metadata["protocol_description"] =
        getSocketProtocolDescription(message->event.bind.socket_protocol);

    // Extract local endpoint information based on the address family
    if (message->event.bind.socket_domain == AF_INET) {
      // IPv4 address handling
      if (message->event.bind.address) {
        char addr_str[INET_ADDRSTRLEN] = {0};
        const struct sockaddr_in* addr =
            (const struct sockaddr_in*)message->event.bind.address;
        inet_ntop(AF_INET, &(addr->sin_addr), addr_str, INET_ADDRSTRLEN);
        ec->local_address = addr_str;
        ec->local_port = ntohs(addr->sin_port);
      }
    } else if (message->event.bind.socket_domain == AF_INET6) {
      // IPv6 address handling
      if (message->event.bind.address) {
        char addr_str[INET6_ADDRSTRLEN] = {0};
        const struct sockaddr_in6* addr =
            (const struct sockaddr_in6*)message->event.bind.address;
        inet_ntop(AF_INET6, &(addr->sin6_addr), addr_str, INET6_ADDRSTRLEN);
        ec->local_address = addr_str;
        ec->local_port = ntohs(addr->sin6_port);
      }
    }
  } break;
  case ES_EVENT_TYPE_NOTIFY_LISTEN: {
    ec->event_type = "listen";
    // Extract socket information
    ec->socket_domain = std::to_string(message->event.listen.socket_domain);
    ec->socket_type = std::to_string(message->event.listen.socket_type);
    ec->socket_protocol = std::to_string(message->event.listen.socket_protocol);

    // Map domain, type, and protocol to human-readable values
    ec->metadata["domain_description"] =
        getSocketDomainDescription(message->event.listen.socket_domain);
    ec->metadata["type_description"] =
        getSocketTypeDescription(message->event.listen.socket_type);
    ec->metadata["protocol_description"] =
        getSocketProtocolDescription(message->event.listen.socket_protocol);

    // Include backlog size as metadata
    ec->metadata["backlog"] = std::to_string(message->event.listen.backlog);
  } break;
  case ES_EVENT_TYPE_NOTIFY_ACCEPT: {
    ec->event_type = "accept";
    // Extract socket information
    ec->socket_domain = std::to_string(message->event.accept.socket_domain);
    ec->socket_type = std::to_string(message->event.accept.socket_type);
    ec->socket_protocol = std::to_string(message->event.accept.socket_protocol);

    // Map domain, type, and protocol to human-readable values
    ec->metadata["domain_description"] =
        getSocketDomainDescription(message->event.accept.socket_domain);
    ec->metadata["type_description"] =
        getSocketTypeDescription(message->event.accept.socket_type);
    ec->metadata["protocol_description"] =
        getSocketProtocolDescription(message->event.accept.socket_protocol);

    // Extract remote endpoint information based on the address family
    if (message->event.accept.socket_domain == AF_INET) {
      // IPv4 address handling
      if (message->event.accept.remote_address) {
        char addr_str[INET_ADDRSTRLEN] = {0};
        const struct sockaddr_in* addr =
            (const struct sockaddr_in*)message->event.accept.remote_address;
        inet_ntop(AF_INET, &(addr->sin_addr), addr_str, INET_ADDRSTRLEN);
        ec->remote_address = addr_str;
        ec->remote_port = ntohs(addr->sin_port);
      }
    } else if (message->event.accept.socket_domain == AF_INET6) {
      // IPv6 address handling
      if (message->event.accept.remote_address) {
        char addr_str[INET6_ADDRSTRLEN] = {0};
        const struct sockaddr_in6* addr =
            (const struct sockaddr_in6*)message->event.accept.remote_address;
        inet_ntop(AF_INET6, &(addr->sin6_addr), addr_str, INET6_ADDRSTRLEN);
        ec->remote_address = addr_str;
        ec->remote_port = ntohs(addr->sin6_port);
      }
    }
  } break;
  case ES_EVENT_TYPE_NOTIFY_UIPC_BIND: {
    ec->event_type = "uipc_bind";
    if (message->event.uipc_bind.dir) {
      ec->path = getStringFromToken(&message->event.uipc_bind.dir->path);
      if (message->event.uipc_bind.filename) {
        ec->path += "/";
        ec->path += getStringFromToken(message->event.uipc_bind.filename);
      }
    }
    ec->socket_domain = std::to_string(message->event.uipc_bind.domain);
    ec->socket_type = std::to_string(message->event.uipc_bind.type);
    ec->socket_protocol = std::to_string(message->event.uipc_bind.protocol);
  } break;
  case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: {
    ec->event_type = "uipc_connect";
    if (message->event.uipc_connect.dir) {
      ec->path = getStringFromToken(&message->event.uipc_connect.dir->path);
      if (message->event.uipc_connect.filename) {
        ec->path += "/";
        ec->path += getStringFromToken(message->event.uipc_connect.filename);
      }
    }
    ec->socket_domain = std::to_string(message->event.uipc_connect.domain);
    ec->socket_type = std::to_string(message->event.uipc_connect.type);
    ec->socket_protocol = std::to_string(message->event.uipc_connect.protocol);
  } break;

  // Mount events
  case ES_EVENT_TYPE_NOTIFY_MOUNT: {
    ec->event_type = "mount";
    if (message->event.mount.statfs) {
      ec->mount_path = message->event.mount.statfs->f_mntonname;
      ec->mount_type = message->event.mount.statfs->f_fstypename;
    }
  } break;
  case ES_EVENT_TYPE_NOTIFY_UNMOUNT: {
    ec->event_type = "unmount";
    if (message->event.unmount.statfs) {
      ec->mount_path = message->event.unmount.statfs->f_mntonname;
      ec->mount_type = message->event.unmount.statfs->f_fstypename;
    }
  } break;

  // Remote thread events
  case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE: {
    ec->event_type = "remote_thread_create";
    if (message->event.remote_thread_create.target) {
      ec->metadata["target_pid"] = std::to_string(audit_token_to_pid(
          message->event.remote_thread_create.target->audit_token));
    }
    ec->metadata["thread_state"] =
        std::to_string(message->event.remote_thread_create.thread_state);
  } break;

  // SSH events
  case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN: {
    ec->event_type = "openssh_login";
    ec->ssh_login_username =
        getStringFromToken(message->event.openssh_login.username);
    ec->metadata["success"] =
        message->event.openssh_login.success ? "true" : "false";
    ec->metadata["result_type"] =
        std::to_string(message->event.openssh_login.result_type);
  } break;
  case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT: {
    ec->event_type = "openssh_logout";
    ec->ssh_login_username =
        getStringFromToken(message->event.openssh_logout.username);
  } break;

  // ScreenSharing events
  case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH: {
    ec->event_type = "screensharing_attach";
    ec->screensharing_type = "attach";
    if (message->event.screensharing_attach.viewer_appliance) {
      ec->screensharing_viewer_app_path =
          getStringFromToken(&message->event.screensharing_attach
                                  .viewer_appliance->executable->path);
    }
    ec->metadata["success"] =
        message->event.screensharing_attach.success ? "true" : "false";
    ec->metadata["type"] =
        std::to_string(message->event.screensharing_attach.type);
  } break;
  case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH: {
    ec->event_type = "screensharing_detach";
    ec->screensharing_type = "detach";
    if (message->event.screensharing_detach.viewer_appliance) {
      ec->screensharing_viewer_app_path =
          getStringFromToken(&message->event.screensharing_detach
                                  .viewer_appliance->executable->path);
    }
    ec->metadata["type"] =
        std::to_string(message->event.screensharing_detach.type);
  } break;

  // Su/sudo events
  case ES_EVENT_TYPE_NOTIFY_SU: {
    ec->event_type = "su";
    if (message->event.su.from_username && message->event.su.to_username) {
      ec->su_from_username =
          getStringFromToken(message->event.su.from_username);
      ec->su_to_username = getStringFromToken(message->event.su.to_username);
    }
    ec->metadata["success"] = message->event.su.success ? "true" : "false";
  } break;
  case ES_EVENT_TYPE_NOTIFY_SUDO: {
    ec->event_type = "sudo";
    ec->sudo_success = message->event.sudo.success;
    if (message->event.sudo.command) {
      ec->sudo_command = getStringFromToken(message->event.sudo.command);
    }
  } break;

  // Authentication events
  case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION: {
    ec->event_type = "authentication";
    ec->metadata["success"] =
        message->event.authentication.success ? "true" : "false";
    ec->metadata["type"] = std::to_string(message->event.authentication.type);
  } break;
  case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION: {
    ec->event_type = "authorization";
    if (message->event.authorization.right) {
      ec->auth_right = getStringFromToken(message->event.authorization.right);
    }
    ec->metadata["result_type"] =
        std::to_string(message->event.authorization.result_type);
  } break;

  // Profile events
  case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD: {
    ec->event_type = "profile_add";
    if (message->event.profile_add.identifier) {
      ec->profile_identifier =
          getStringFromToken(message->event.profile_add.identifier);
    }
    if (message->event.profile_add.uuid) {
      ec->profile_uuid = getStringFromToken(message->event.profile_add.uuid);
    }
  } break;
  case ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE: {
    ec->event_type = "profile_remove";
    if (message->event.profile_remove.identifier) {
      ec->profile_identifier =
          getStringFromToken(message->event.profile_remove.identifier);
    }
    if (message->event.profile_remove.uuid) {
      ec->profile_uuid = getStringFromToken(message->event.profile_remove.uuid);
    }
  } break;

  // XPC events
  case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT: {
    ec->event_type = "xpc_connect";
    if (message->event.xpc_connect.service_name) {
      ec->metadata["service_name"] =
          getStringFromToken(message->event.xpc_connect.service_name);
    }
  } break;

  // Kernel Extension events
  case ES_EVENT_TYPE_NOTIFY_KEXTLOAD: {
    ec->event_type = "kextload";

    // Basic kext information
    if (message->event.kextload.identifier) {
      ec->metadata["kext_id"] =
          getStringFromToken(message->event.kextload.identifier);
    }
    if (message->event.kextload.path) {
      ec->metadata["kext_path"] =
          getStringFromToken(&message->event.kextload.path->path);
    }
    if (message->event.kextload.version) {
      ec->metadata["kext_version"] =
          getStringFromToken(message->event.kextload.version);
    }

    // Enhanced kext metadata
    if (message->event.kextload.signing_id.data != nullptr) {
      ec->metadata["kext_signing_id"] =
          getStringFromToken(&message->event.kextload.signing_id);
    }
    if (message->event.kextload.team_id.data != nullptr) {
      ec->metadata["kext_team_id"] =
          getStringFromToken(&message->event.kextload.team_id);
    }

    // Generate code signing status information
    ec->metadata["kext_platform_binary"] =
        message->event.kextload.is_platform_binary ? "true" : "false";

    // Extract CD hash if available
    std::stringstream hash;
    for (unsigned char i : message->event.kextload.cdhash) {
      hash << std::hex << std::setfill('0') << std::setw(2)
           << static_cast<unsigned int>(i);
    }
    auto cdhash = hash.str();
    if (!cdhash.empty() &&
        cdhash.find_first_not_of(cdhash.front()) != std::string::npos) {
      ec->metadata["kext_cdhash"] = cdhash;
    }

    // Determine signature status based on codesigning flags
    unsigned int sigflags = message->event.kextload.signing_flags;
    if (sigflags & 0x0001) { // CS_VALID
      ec->metadata["kext_signature_status"] = "valid";
    } else if (sigflags & 0x0002) { // CS_ADHOC
      ec->metadata["kext_signature_status"] = "adhoc";
    } else {
      ec->metadata["kext_signature_status"] = "unsigned";
    }

    // Security assessment
    if (!(sigflags & 0x0001) || (sigflags & 0x0002)) {
      ec->metadata["kext_security_risk"] = "high";
    } else if (!(message->event.kextload.is_platform_binary)) {
      ec->metadata["kext_security_risk"] = "medium";
    } else {
      ec->metadata["kext_security_risk"] = "low";
    }
  } break;

  case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD: {
    ec->event_type = "kextunload";

    // Kext identifiers
    if (message->event.kextunload.identifier) {
      ec->metadata["kext_id"] =
          getStringFromToken(message->event.kextunload.identifier);
    }

    // For kextunload events, we don't have as much metadata available from the
    // API But we can add some informative values
    if (message->process && message->process->executable) {
      ec->metadata["unload_process"] =
          getStringFromToken(&message->process->executable->path);
    }
  } break;

  case ES_EVENT_TYPE_NOTIFY_SYSCTL: {
    ec->event_type = "sysctl";

    // Basic sysctl information
    if (message->event.sysctl.name) {
      ec->metadata["sysctl_name"] =
          getStringFromToken(message->event.sysctl.name);
    }

    // Determine operation type
    switch (message->event.sysctl.type) {
    case ES_SYSCTL_TYPE_NODE:
      ec->metadata["sysctl_type"] = "node";
      break;
    case ES_SYSCTL_TYPE_INT:
      ec->metadata["sysctl_type"] = "int";
      break;
    case ES_SYSCTL_TYPE_STRING:
      ec->metadata["sysctl_type"] = "string";
      break;
    case ES_SYSCTL_TYPE_QUAD:
      ec->metadata["sysctl_type"] = "quad";
      break;
    case ES_SYSCTL_TYPE_STRUCT:
      ec->metadata["sysctl_type"] = "struct";
      break;
    default:
      ec->metadata["sysctl_type"] = "unknown";
      break;
    }

    // Extract operation information
    switch (message->event.sysctl.filter) {
    case ES_SYSCTL_FILTER_READ:
      ec->metadata["sysctl_operation"] = "read";
      break;
    case ES_SYSCTL_FILTER_WRITE:
      ec->metadata["sysctl_operation"] = "write";
      break;
    default:
      ec->metadata["sysctl_operation"] = "unknown";
      break;
    }

    // For string-type sysctl values, extract the new value (if available)
    if (message->event.sysctl.type == ES_SYSCTL_TYPE_STRING &&
        message->event.sysctl.filter == ES_SYSCTL_FILTER_WRITE &&
        message->event.sysctl.data) {
      ec->metadata["sysctl_value"] =
          getStringFromToken(message->event.sysctl.data);
    }

    // Security assessment for sysctl operations
    // Special attention to security-related sysctls
    std::string name = ec->metadata["sysctl_name"];
    if ((name.find("kern.") == 0 || name.find("security.") == 0) &&
        ec->metadata["sysctl_operation"] == "write") {
      ec->metadata["sysctl_security_risk"] = "high";
    } else if (ec->metadata["sysctl_operation"] == "write") {
      ec->metadata["sysctl_security_risk"] = "medium";
    } else {
      ec->metadata["sysctl_security_risk"] = "low";
    }
  } break;

  // Memory protection events
  case ES_EVENT_TYPE_NOTIFY_MMAP: {
    ec->event_type = "mmap";

    // Capture memory protection flags
    ec->metadata["protection"] = std::to_string(message->event.mmap.protection);

    // Add human-readable protection flags
    std::vector<std::string> prot_flags;
    if (message->event.mmap.protection & PROT_READ) {
      prot_flags.push_back("read");
    }
    if (message->event.mmap.protection & PROT_WRITE) {
      prot_flags.push_back("write");
    }
    if (message->event.mmap.protection & PROT_EXEC) {
      prot_flags.push_back("exec");
    }
    if (message->event.mmap.protection == PROT_NONE) {
      prot_flags.push_back("none");
    }

    ec->metadata["protection_flags"] = boost::algorithm::join(prot_flags, "|");

    // Capture mmap flags
    ec->metadata["flags"] = std::to_string(message->event.mmap.flags);

    // Capture file descriptor information if mapping a file
    ec->metadata["fd"] = std::to_string(message->event.mmap.fd);

    // Capture address information if available
    if (message->event.mmap.file) {
      ec->path = getStringFromToken(&message->event.mmap.file->path);
    }

    // Memory address and size
    ec->metadata["address"] =
        std::to_string(reinterpret_cast<uintptr_t>(message->event.mmap.addr));
    ec->metadata["length"] = std::to_string(message->event.mmap.length);

    // Offset
    ec->metadata["offset"] = std::to_string(message->event.mmap.offset);

    // Determine if this is a shared or private mapping
    if (message->event.mmap.flags & MAP_SHARED) {
      ec->metadata["mapping_type"] = "shared";
    } else if (message->event.mmap.flags & MAP_PRIVATE) {
      ec->metadata["mapping_type"] = "private";
    }

    // Determine if this is potentially executable memory
    bool is_executable = (message->event.mmap.protection & PROT_EXEC) != 0;
    ec->metadata["is_executable"] = is_executable ? "true" : "false";

    // Determine severity based on executable + writable memory (potentially
    // malicious)
    bool is_writable = (message->event.mmap.protection & PROT_WRITE) != 0;
    if (is_executable && is_writable) {
      ec->metadata["severity"] = "high";
    } else if (is_executable) {
      ec->metadata["severity"] = "medium";
    } else {
      ec->metadata["severity"] = "low";
    }
  } break;

  case ES_EVENT_TYPE_NOTIFY_MPROTECT: {
    ec->event_type = "mprotect";

    // Memory address and size
    ec->metadata["address"] = std::to_string(
        reinterpret_cast<uintptr_t>(message->event.mprotect.addr));
    ec->metadata["length"] = std::to_string(message->event.mprotect.length);

    // Capture old and new protection flags
    ec->metadata["old_protection"] =
        std::to_string(message->event.mprotect.protection);
    ec->metadata["new_protection"] =
        std::to_string(message->event.mprotect.new_protection);

    // Add human-readable old protection flags
    std::vector<std::string> old_prot_flags;
    if (message->event.mprotect.protection & PROT_READ) {
      old_prot_flags.push_back("read");
    }
    if (message->event.mprotect.protection & PROT_WRITE) {
      old_prot_flags.push_back("write");
    }
    if (message->event.mprotect.protection & PROT_EXEC) {
      old_prot_flags.push_back("exec");
    }
    if (message->event.mprotect.protection == PROT_NONE) {
      old_prot_flags.push_back("none");
    }

    ec->metadata["old_protection_flags"] =
        boost::algorithm::join(old_prot_flags, "|");

    // Add human-readable new protection flags
    std::vector<std::string> new_prot_flags;
    if (message->event.mprotect.new_protection & PROT_READ) {
      new_prot_flags.push_back("read");
    }
    if (message->event.mprotect.new_protection & PROT_WRITE) {
      new_prot_flags.push_back("write");
    }
    if (message->event.mprotect.new_protection & PROT_EXEC) {
      new_prot_flags.push_back("exec");
    }
    if (message->event.mprotect.new_protection == PROT_NONE) {
      new_prot_flags.push_back("none");
    }

    ec->metadata["new_protection_flags"] =
        boost::algorithm::join(new_prot_flags, "|");

    // Determine if this is adding executable permission (potentially malicious)
    bool adding_exec =
        ((message->event.mprotect.protection & PROT_EXEC) == 0) &&
        ((message->event.mprotect.new_protection & PROT_EXEC) != 0);
    ec->metadata["adding_executable"] = adding_exec ? "true" : "false";

    // Determine severity based on adding executable permission to writable
    // memory
    bool is_writable =
        (message->event.mprotect.new_protection & PROT_WRITE) != 0;
    bool is_executable =
        (message->event.mprotect.new_protection & PROT_EXEC) != 0;

    if (adding_exec && is_writable) {
      ec->metadata["severity"] = "high";
    } else if (adding_exec || (is_executable && is_writable)) {
      ec->metadata["severity"] = "medium";
    } else {
      ec->metadata["severity"] = "low";
    }
  } break;

  // Handle other events
  default: {
    // Generic event type extraction
    std::string event_type_name = "unknown";
    for (const auto& pair : kESEventNameMap) {
      if (pair.second == message->event_type) {
        event_type_name = pair.first;
        break;
      }
    }
    ec->event_type = event_type_name;

    VLOG(1) << "EndpointSecurity unhandled event type: " << event_type_name;
  } break;
  }

  EventFactory::fire<EndpointSecurityPublisher>(ec);
}

bool EndpointSecurityPublisher::shouldFire(
    const EndpointSecuritySubscriptionContextRef& sc,
    const EndpointSecurityEventContextRef& ec) const {
  return true;
}

} // namespace osquery
