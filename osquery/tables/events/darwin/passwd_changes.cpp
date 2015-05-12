/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>
#include <string>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/events/darwin/fsevents.h"

namespace osquery {
namespace tables {

const std::vector<std::string> kDarwinPasswdPaths = {
    "/etc/passwd", "/private/etc/passwd", "/etc/shadow", "/private/etc/shadow",
};

/**
 * @brief Track time, action changes to /etc/passwd
 *
 * This is mostly an example EventSubscriber implementation.
 */
class PasswdChangesEventSubscriber
    : public EventSubscriber<FSEventsEventPublisher> {
 public:
  Status init();

  /**
   * @brief This exports a single Callback for INotifyEventPublisher events.
   *
   * @param ec The EventCallback type receives an EventContextRef substruct
   * for the INotifyEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Was the callback successful.
   */
  Status Callback(const FSEventsEventContextRef& ec, const void* user_data);
};

/**
 * @brief Each EventSubscriber must register itself so the init method is
 *called.
 *
 * This registers PasswdChangesEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(PasswdChangesEventSubscriber, "event_subscriber", "passwd_changes");

Status PasswdChangesEventSubscriber::init() {
  for (const auto& path : kDarwinPasswdPaths) {
    auto mc = createSubscriptionContext();
    mc->path = path;
    subscribe(&PasswdChangesEventSubscriber::Callback, mc, nullptr);
  }

  return Status(0, "OK");
}

Status PasswdChangesEventSubscriber::Callback(const FSEventsEventContextRef& ec,
                                              const void* user_data) {
  Row r;
  r["action"] = ec->action;
  r["time"] = ec->time_string;
  r["target_path"] = ec->path;
  r["transaction_id"] = INTEGER(ec->transaction_id);
  if (ec->action != "") {
    add(r, ec->time);
  }
  return Status(0, "OK");
}
}
}
