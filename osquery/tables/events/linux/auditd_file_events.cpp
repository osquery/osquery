/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/events/linux/auditfim.h"

#include <osquery/config.h>
#include <osquery/events.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include <asm/unistd_64.h>

namespace osquery {

FLAG(bool,
     audit_allow_file_events,
     true,
     "Allow the audit publisher to install file event monitoring rules");

namespace tables {
extern long getUptime();
}

class AuditFimEventSubscriber : public EventSubscriber<AuditFimEventPublisher> {
 public:
  Status init() override;
  Status Callback(const ECRef& event_context,
                  const SCRef& subscription_context);
};

REGISTER(AuditFimEventSubscriber, "event_subscriber", "auditd_file_events");

Status AuditFimEventSubscriber::init() {
  auto sc = createSubscriptionContext();
  subscribe(&AuditFimEventSubscriber::Callback, sc);

  return Status(0, "OK");
}

Status AuditFimEventSubscriber::Callback(const ECRef& event_context,
                                         const SCRef& subscription_context) {
  std::map<std::string, std::string> test;

  test["operation"] = "operation";
  test["pid"] = "pid";
  test["ppid"] = "ppid";
  test["cwd"] = "cwd";
  test["inode"] = "inode";
  test["name"] = "name";
  test["canonical_path"] = "canonical_path";
  test["time"] = "time";
  test["eid"] = "eid";

  add(test);
  return Status(0, "OK");
}
}
