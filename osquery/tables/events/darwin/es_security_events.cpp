/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/darwin/es_event_categories.h>
#include <osquery/events/darwin/es_utils.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/events/darwin/es_security_events.h>

namespace osquery {

class ESSecurityEventSubscriber
    : public EventSubscriber<EndpointSecurityPublisher> {
 public:
  Status init() override;
  Status Callback(const EndpointSecurityEventContextRef& ec,
                  const EndpointSecuritySubscriptionContextRef& sc);
};

REGISTER(ESSecurityEventSubscriber, "event_subscriber", "es_security_events");

Status ESSecurityEventSubscriber::init() {
  if (__builtin_available(macos 10.15, *)) {
    auto sc = createSubscriptionContext();

    // Get all enabled event types from the configuration system
    sc->es_event_subscriptions_ = getEnabledEventTypes();

    // Filter out process events which are handled by the process events
    // subscriber
    auto it = std::remove_if(sc->es_event_subscriptions_.begin(),
                             sc->es_event_subscriptions_.end(),
                             [](es_event_type_t type) {
                               return type == ES_EVENT_TYPE_NOTIFY_EXEC ||
                                      type == ES_EVENT_TYPE_NOTIFY_FORK ||
                                      type == ES_EVENT_TYPE_NOTIFY_EXIT;
                             });
    sc->es_event_subscriptions_.erase(it, sc->es_event_subscriptions_.end());

    VLOG(1) << "ESSecurityEventSubscriber subscribed to "
            << sc->es_event_subscriptions_.size() << " event types";

    subscribe(&ESSecurityEventSubscriber::Callback, sc);
    return Status::success();
  }
  return Status(1, "EndpointSecurity is only available on macOS 10.15+");
}

Status ESSecurityEventSubscriber::Callback(
    const EndpointSecurityEventContextRef& ec,
    const EndpointSecuritySubscriptionContextRef& sc) {
  // Skip process events, they're handled by the process events subscriber
  if (ec->event_type == "exec" || ec->event_type == "fork" ||
      ec->event_type == "exit") {
    return Status::success();
  }

  Row r;

  // Core event metadata
  r["version"] = INTEGER(ec->version);
  r["seq_num"] = BIGINT(ec->seq_num);
  r["global_seq_num"] = BIGINT(ec->global_seq_num);
  r["event_type"] = ec->event_type;
  r["time"] = BIGINT(ec->time);

  // Event categorization
  r["category"] = getEventCategoryString(ec->es_event);
  r["severity"] = getEventSeverityString(ec->es_event);

  // Process context
  r["pid"] = BIGINT(ec->pid);
  r["pidversion"] = INTEGER(ec->pidversion);
  r["path"] = ec->path;
  r["username"] = ec->username;

  // Human-readable description
  r["description"] = getEventDescription(ec->event_type, ec->metadata);

  // Handle event-specific fields based on event type

  // UID/GID change events
  if (ec->event_type == "setuid" || ec->event_type == "seteuid") {
    r["target_uid"] = BIGINT(ec->target_uid);
  } else if (ec->event_type == "setreuid") {
    r["target_uid"] = BIGINT(ec->target_uid);
    r["target_euid"] = BIGINT(ec->target_euid);
  } else if (ec->event_type == "setgid" || ec->event_type == "setegid") {
    r["target_gid"] = BIGINT(ec->target_gid);
  } else if (ec->event_type == "setregid") {
    r["target_gid"] = BIGINT(ec->target_gid);
    r["target_egid"] = BIGINT(ec->target_egid);
  }

  // Signal events
  else if (ec->event_type == "signal") {
    r["signal_number"] = INTEGER(ec->signal_number);
    if (!ec->metadata.empty() && ec->metadata.count("target_pid") > 0) {
      r["target_pid"] = ec->metadata.at("target_pid");
    }
  }

  // Socket events
  else if (ec->event_type == "socket" || ec->event_type == "connect" ||
           ec->event_type == "bind" || ec->event_type == "listen" ||
           ec->event_type == "accept" || ec->event_type == "uipc_bind" ||
           ec->event_type == "uipc_connect") {
    r["socket_domain"] = ec->socket_domain;
    r["socket_type"] = ec->socket_type;
    r["socket_protocol"] = ec->socket_protocol;

    // Add helpful human-readable socket information
    if (!ec->metadata.empty()) {
      if (ec->metadata.count("domain_description") > 0) {
        r["socket_domain_description"] = ec->metadata.at("domain_description");
      }
      if (ec->metadata.count("type_description") > 0) {
        r["socket_type_description"] = ec->metadata.at("type_description");
      }
      if (ec->metadata.count("protocol_description") > 0) {
        r["socket_protocol_description"] =
            ec->metadata.at("protocol_description");
      }
    }

    // Add remote address information
    if (ec->event_type == "connect" || ec->event_type == "accept") {
      if (!ec->remote_address.empty()) {
        r["remote_address"] = ec->remote_address;
        r["remote_port"] = INTEGER(ec->remote_port);
      }
    }

    // Add local address information
    if (ec->event_type == "bind" || ec->event_type == "listen") {
      if (!ec->local_address.empty()) {
        r["local_address"] = ec->local_address;
        r["local_port"] = INTEGER(ec->local_port);
      }
    }

    // For UNIX domain sockets
    if (ec->event_type == "uipc_bind" || ec->event_type == "uipc_connect") {
      if (!ec->path.empty()) {
        r["socket_path"] = ec->path;
      }
    }

    // Add connection state and flags for connection-related events
    if (ec->event_type == "listen" && !ec->metadata.empty() &&
        ec->metadata.count("backlog") > 0) {
      r["backlog"] = ec->metadata.at("backlog");
    }
  }

  // Mount events
  else if (ec->event_type == "mount" || ec->event_type == "unmount") {
    r["mount_path"] = ec->mount_path;
    r["mount_type"] = ec->mount_type;
  }

  // SSH events
  else if (ec->event_type == "openssh_login" ||
           ec->event_type == "openssh_logout") {
    r["ssh_login_username"] = ec->ssh_login_username;

    if (!ec->metadata.empty()) {
      if (ec->metadata.count("success") > 0) {
        r["success"] = ec->metadata.at("success");
      }
      if (ec->metadata.count("result_type") > 0) {
        r["result_type"] = ec->metadata.at("result_type");
      }
    }
  }

  // ScreenSharing events
  else if (ec->event_type == "screensharing_attach" ||
           ec->event_type == "screensharing_detach") {
    r["screensharing_type"] = ec->screensharing_type;
    r["screensharing_viewer_app_path"] = ec->screensharing_viewer_app_path;

    if (!ec->metadata.empty()) {
      if (ec->metadata.count("success") > 0) {
        r["success"] = ec->metadata.at("success");
      }
      if (ec->metadata.count("type") > 0) {
        r["connection_type"] = ec->metadata.at("type");
      }
    }
  }

  // Session events
  else if (ec->event_type == "lw_session_login" ||
           ec->event_type == "lw_session_logout" ||
           ec->event_type == "lw_session_lock" ||
           ec->event_type == "lw_session_unlock" ||
           ec->event_type == "login_login" ||
           ec->event_type == "login_logout") {
    if (!ec->metadata.empty()) {
      if (ec->metadata.count("username") > 0) {
        r["username"] = ec->metadata.at("username");
      }
      if (ec->metadata.count("success") > 0) {
        r["success"] = ec->metadata.at("success");
      }
      if (ec->metadata.count("uid") > 0) {
        r["target_uid"] = ec->metadata.at("uid");
      }
    }
  }

  // SU events
  else if (ec->event_type == "su") {
    r["su_from_username"] = ec->su_from_username;
    r["su_to_username"] = ec->su_to_username;

    if (!ec->metadata.empty() && ec->metadata.count("success") > 0) {
      r["success"] = ec->metadata.at("success");
    }
  }

  // Sudo events
  else if (ec->event_type == "sudo") {
    r["sudo_command"] = ec->sudo_command;
    r["success"] = ec->sudo_success ? "true" : "false";
  }

  // Authentication events
  else if (ec->event_type == "authentication" ||
           ec->event_type == "authorization") {
    if (ec->event_type == "authorization") {
      r["auth_right"] = ec->auth_right;
    }

    if (!ec->metadata.empty()) {
      if (ec->metadata.count("success") > 0) {
        r["success"] = ec->metadata.at("success");
      }
      if (ec->metadata.count("type") > 0) {
        r["auth_type"] = ec->metadata.at("type");
      }
      if (ec->metadata.count("result_type") > 0) {
        r["result_type"] = ec->metadata.at("result_type");
      }
    }
  }

  // TCC events
  else if (ec->event_type == "tcc_modify") {
    if (!ec->metadata.empty()) {
      if (ec->metadata.count("service") > 0) {
        r["auth_right"] = ec->metadata.at("service");
      }
      if (ec->metadata.count("app_path") > 0) {
        r["path"] = ec->metadata.at("app_path");
      }
      if (ec->metadata.count("allowed") > 0) {
        r["success"] = ec->metadata.at("allowed");
      }
      if (ec->metadata.count("operation_type") > 0) {
        r["result_type"] = ec->metadata.at("operation_type");
      }
    }
  }

  // Profile events
  else if (ec->event_type == "profile_add" ||
           ec->event_type == "profile_remove") {
    r["profile_identifier"] = ec->profile_identifier;
    r["profile_uuid"] = ec->profile_uuid;
  }

  // XPC events
  else if (ec->event_type == "xpc_connect") {
    if (!ec->metadata.empty() && ec->metadata.count("service_name") > 0) {
      r["service_name"] = ec->metadata.at("service_name");
    }
  }

  // Memory protection events
  else if (ec->event_type == "mmap" || ec->event_type == "mprotect") {
    if (!ec->metadata.empty()) {
      // Memory address and size information
      if (ec->metadata.count("address") > 0) {
        r["memory_address"] = ec->metadata.at("address");
      }
      if (ec->metadata.count("length") > 0) {
        r["memory_size"] = ec->metadata.at("length");
      }

      // Protection flags
      if (ec->event_type == "mmap") {
        if (ec->metadata.count("protection_flags") > 0) {
          r["memory_protection"] = ec->metadata.at("protection_flags");
        }
        if (ec->metadata.count("mapping_type") > 0) {
          r["memory_type"] = ec->metadata.at("mapping_type");
        }
        if (ec->metadata.count("is_executable") > 0) {
          r["memory_is_executable"] = ec->metadata.at("is_executable");
        }
      } else if (ec->event_type == "mprotect") {
        if (ec->metadata.count("old_protection_flags") > 0) {
          r["memory_old_protection"] = ec->metadata.at("old_protection_flags");
        }
        if (ec->metadata.count("new_protection_flags") > 0) {
          r["memory_protection"] = ec->metadata.at("new_protection_flags");
        }
        if (ec->metadata.count("adding_executable") > 0) {
          r["memory_is_executable"] = ec->metadata.at("adding_executable");
        }
      }

      // Add severity information for potentially malicious memory operations
      if (ec->metadata.count("severity") > 0) {
        r["memory_severity"] = ec->metadata.at("severity");
      }
    }
  }

  // OpenDirectory events
  else if (ec->event_type == "od_group_add" ||
           ec->event_type == "od_group_remove" ||
           ec->event_type == "od_group_set" ||
           ec->event_type == "od_modify_password") {
    if (!ec->metadata.empty()) {
      if (ec->metadata.count("username") > 0) {
        r["username"] = ec->metadata.at("username");
      }
      if (ec->metadata.count("group_name") > 0) {
        r["group_name"] = ec->metadata.at("group_name");
      }
      if (ec->metadata.count("success") > 0) {
        r["success"] = ec->metadata.at("success");
      }
    }
  }

  // Kernel extension events
  else if (ec->event_type == "kextload" || ec->event_type == "kextunload") {
    if (!ec->metadata.empty()) {
      if (ec->metadata.count("kext_path") > 0) {
        r["path"] = ec->metadata.at("kext_path");
      }
      if (ec->metadata.count("kext_id") > 0) {
        r["kext_id"] = ec->metadata.at("kext_id");
      }
      if (ec->metadata.count("kext_version") > 0) {
        r["kext_version"] = ec->metadata.at("kext_version");
      }

      // Enhanced kext metadata
      if (ec->metadata.count("kext_team_id") > 0) {
        r["kext_team_id"] = ec->metadata.at("kext_team_id");
      }
      if (ec->metadata.count("kext_signing_id") > 0) {
        r["kext_signing_id"] = ec->metadata.at("kext_signing_id");
      }
      if (ec->metadata.count("kext_platform_binary") > 0) {
        r["kext_platform_binary"] = ec->metadata.at("kext_platform_binary");
      }
      if (ec->metadata.count("kext_cdhash") > 0) {
        r["kext_cdhash"] = ec->metadata.at("kext_cdhash");
      }
      if (ec->metadata.count("kext_signature_status") > 0) {
        r["kext_validation"] = ec->metadata.at("kext_signature_status");
      }
    }
  }

  // System control events
  else if (ec->event_type == "sysctl") {
    if (!ec->metadata.empty()) {
      if (ec->metadata.count("sysctl_name") > 0) {
        r["sysctl_name"] = ec->metadata.at("sysctl_name");
      }
      if (ec->metadata.count("sysctl_type") > 0) {
        r["sysctl_type"] = ec->metadata.at("sysctl_type");
      }
      if (ec->metadata.count("sysctl_operation") > 0) {
        r["sysctl_operation"] = ec->metadata.at("sysctl_operation");
      }
      if (ec->metadata.count("sysctl_value") > 0) {
        r["sysctl_value"] = ec->metadata.at("sysctl_value");
      }
    }
  }

  // Ptrace/debugging events
  else if (ec->event_type == "ptrace" || ec->event_type == "trace") {
    if (!ec->metadata.empty()) {
      if (ec->metadata.count("target_pid") > 0) {
        r["target_pid"] = ec->metadata.at("target_pid");
      }
    }
  }

  // Process suspend/resume events
  else if (ec->event_type == "proc_suspend_resume") {
    if (!ec->metadata.empty()) {
      if (ec->metadata.count("target_pid") > 0) {
        r["target_pid"] = ec->metadata.at("target_pid");
      }
      if (ec->metadata.count("suspended") > 0) {
        r["thread_state"] =
            ec->metadata.at("suspended") == "true" ? "suspended" : "resumed";
      }
    }
  }

  // Include all remaining metadata values
  for (const auto& meta_pair : ec->metadata) {
    if (r.count(meta_pair.first) == 0) {
      r[meta_pair.first] = meta_pair.second;
    }
  }

  sc->row_list = {r};
  if (!sc->row_list.empty()) {
    addBatch(sc->row_list);
  }
  return Status::success();
}

QueryData genESSecurityEvents(QueryContext& context) {
  QueryData results;
  auto es_sc = ESSecurityEventSubscriber::get();
  if (es_sc == nullptr) {
    return results;
  }

  return es_sc->genTable(context);
}
} // namespace osquery