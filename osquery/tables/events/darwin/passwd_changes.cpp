// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <glog/logging.h>

#include <osquery/core.h>
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
  DECLARE_SUBSCRIBER("PasswdChangesEventSubscriber");

 public:
  void init();

  /**
   * @brief This exports a single Callback for INotifyEventPublisher events.
   *
   * @param ec The EventCallback type receives an EventContextRef substruct
   * for the INotifyEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Was the callback successful.
   */
  Status Callback(const FSEventsEventContextRef ec);
};

/**
 * @brief Each EventSubscriber must register itself so the init method is
 *called.
 *
 * This registers PasswdChangesEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER_EVENTSUBSCRIBER(PasswdChangesEventSubscriber);

void PasswdChangesEventSubscriber::init() {
  for (const auto& path : kDarwinPasswdPaths) {
    auto mc = createSubscriptionContext();
    mc->path = path;
    subscribe(&PasswdChangesEventSubscriber::Callback, mc);
  }
}

Status PasswdChangesEventSubscriber::Callback(
    const FSEventsEventContextRef ec) {
  Row r;
  r["action"] = ec->action;
  r["time"] = ec->time_string;
  r["target_path"] = ec->path;
  r["transaction_id"] = INTEGER(ec->fsevent_id);
  if (ec->action != "") {
    add(r, ec->time);
  }
  return Status(0, "OK");
}
}
}
