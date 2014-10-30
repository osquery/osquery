// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/events/linux/inotify.h"

namespace osquery {
namespace tables {

/**
 * @brief Track time, action changes to /etc/passwd
 *
 * This is mostly an example EventSubscriber implementation.
 */
class PasswdChangesEventSubscriber : public EventSubscriber {
  DECLARE_EVENTSUBSCRIBER(PasswdChangesEventSubscriber, INotifyEventPublisher);
  DECLARE_CALLBACK(Callback, INotifyEventContext);

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
  Status Callback(const INotifyEventContextRef ec);
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
  auto mc = INotifyEventPublisher::createSubscriptionContext();
  mc->path = "/etc/passwd";
  mc->mask = IN_ATTRIB | IN_MODIFY | IN_DELETE | IN_CREATE;
  BIND_CALLBACK(Callback, mc);
}

Status PasswdChangesEventSubscriber::Callback(const INotifyEventContextRef ec) {
  Row r;
  r["action"] = ec->action;
  r["time"] = ec->time_string;
  r["target_path"] = ec->path;
  r["transaction_id"] = boost::lexical_cast<std::string>(ec->event->cookie);
  if (ec->action != "" && ec->action != "OPENED") {
    // A callback is somewhat useless unless it changes the EventSubscriber
    // state
    // or calls `add` to store a marked up event.
    add(r, ec->time);
  }
  return Status(0, "OK");
}
}
}
