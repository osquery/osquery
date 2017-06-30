/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/core/conversions.h>

#include "osquery/events/linux/audit.h"

#include <sstream>
#include <cstdlib>
#include <array>
#include <unordered_map>
#include <iostream>

#include <boost/filesystem.hpp>
namespace boost_fs = boost::filesystem;

namespace osquery {

#define AUDIT_SYSCALL_READ 0
#define AUDIT_SYSCALL_WRITE 1
#define AUDIT_SYSCALL_OPEN 2
#define AUDIT_SYSCALL_CLOSE 3

#define SUBSCRIBED_EVENT_TYPES {AUDIT_SYSCALL, AUDIT_CWD, AUDIT_PATH}
#define SUBSCRIBED_SYSCALL_NUMBERS {AUDIT_SYSCALL_WRITE, AUDIT_SYSCALL_OPEN}

// Depend on the external getUptime table method.
namespace tables {
extern long getUptime();
}

bool ProcessFileEventUpdate(size_t type, const AuditFields& fields, AuditFields& r) {
  assert(type == AUDIT_SYSCALL || type == AUDIT_PATH || type == AUDIT_CWD);

  if (type == AUDIT_SYSCALL)
  {
    const auto &syscall_number_it = fields.find("syscall");
    if (syscall_number_it == fields.end()) {
      VLOG(1) << "Received an AUDIT_SYSCALL event with no syscall number field!";
      return false;
    }

    std::size_t syscall_number;
    Status conversion = safeStrtoul(syscall_number_it->second, 10, syscall_number);
    if (!conversion.ok()) {
      VLOG(1) << "Invalid syscall number found in the AUDIT_SYSCALL event!";
      return false;
    }

    switch (syscall_number)
    {
      case AUDIT_SYSCALL_WRITE: {
      r["operation"] = "write";
        break;
    }

      case AUDIT_SYSCALL_OPEN: {
      r["operation"] = "open";
        break;
      }

      default: {
        VLOG(1) << "Invalid syscall number!";
        return false;
      }
    }

    r["pid"] = (fields.count("pid")) ? fields.at("pid") : "0";
    r["ppid"] = (fields.count("ppid")) ? fields.at("ppid") : "0";
  }

  else if (type == AUDIT_CWD) {
    r["cwd"] = (fields.count("cwd")) ? fields.at("cwd") : "(null)";

  } else { // AUDIT_PATH
    r["inode"] = (fields.count("inode")) ? fields.at("inode") : "0";
    r["name"] = (fields.count("name")) ? fields.at("name") : "(null)";

    boost_fs::path path(r["name"]);
    boost_fs::path cwd(r["cwd"]);

    boost::system::error_code conversion_ok;
    boost_fs::path canonical_path = boost_fs::canonical(path, cwd, conversion_ok);
    if (!conversion_ok) {
      r["canonical_path"] = "N/A";
    } else {
      r["canonical_path"] = canonical_path.string();
      if (r["canonical_path"].empty())
        r["canonical_path"] = path.normalize().string();
    }

    if (!conversion_ok)
      std::cout << "CONVERSION ERROR: "<< conversion_ok.message() << std::endl;

    std::cout << r["cwd"] << " " << r["name"] << " -> "<< r["canonical_path"] << std::endl;

    //
    // DEBUG
    //

    /*auto L_GetField = [&fields, &r](const std::string &field_name, const std::string &default_value) -> std::string {
      auto r_it = r.find(field_name);
      if (r_it != r.end())
      return r_it->second;

      auto fields_it = fields.find(field_name);
      if (fields_it != fields.end())
        return fields_it->second;

      return default_value;
    };

    std::cout << L_GetField("ppid", "0") << "\t";
    std::cout << L_GetField("pid", "0") << "\t";
    std::cout << L_GetField("operation", "(null)") << "\t";
    std::cout << L_GetField("inode", "N/A") << "\t";
    std::cout << L_GetField("cwd", "(null)") << "\t";
    std::cout << L_GetField("name", "(null)") << std::endl;*/
  }

  return true;
}

class AuditdFileEventSubscriber : public EventSubscriber<AuditEventPublisher> {
 public:
  /// The process event subscriber declares an audit event type subscription.
  Status init() override;

  /// Kernel events matching the event type will fire.
  Status Callback(const ECRef& ec, const SCRef& sc);

 private:
  AuditAssembler asm_;
  std::unordered_map<std::string, bool> monitored_file_list_;
};

REGISTER(AuditdFileEventSubscriber, "event_subscriber", "auditd_file_events");

Status AuditdFileEventSubscriber::init() {
  asm_.start(20, SUBSCRIBED_EVENT_TYPES, &ProcessFileEventUpdate);

  auto sc = createSubscriptionContext();
  sc->types = SUBSCRIBED_EVENT_TYPES;
  for (const auto &rule : SUBSCRIBED_SYSCALL_NUMBERS)
    sc->rules.push_back({rule, ""});

  subscribe(&AuditdFileEventSubscriber::Callback, sc);

  // Acquire the user settings
  /// \todo Optimize the search
  auto parser = Config::getParser("file_paths");
  auto& accesses = parser->getData().get_child("file_accesses");

  Config::get().files([this, &accesses](const std::string& category,
                                        const std::vector<std::string>& files) {
    // false: only track accesses
    // true: also track writes
    for (const auto& file : files)
      monitored_file_list_[file] = (accesses.count(category) > 0);
  });

  return Status(0, "OK");
}

Status AuditdFileEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {

  if (ec->fields.count("success") && ec->fields.at("success") == "no")
    return Status(0, "OK");

  auto fields = asm_.add(ec->audit_id, ec->type, ec->fields);
  if (!fields.is_initialized())
    return Status(0, "OK");

  add(*fields);
  return Status(0, "OK");
}
}
