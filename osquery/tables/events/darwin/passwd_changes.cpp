// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/events/darwin/fsevents.h"

namespace osquery {
namespace tables {

const std::vector<std::string> kDarwinPasswdPaths = {"/etc/passwd",
                                                     "/private/etc/passwd",
                                                     "/etc/shadow",
                                                     "/private/etc/shadow", };

/**
 * @brief Track time, action changes to /etc/passwd
 *
 * This is mostly an example EventModule implementation.
 */
class PasswdChangesEventModule : public EventModule {
  DECLARE_EVENTMODULE(PasswdChangesEventModule, FSEventsEventType);
  DECLARE_CALLBACK(Callback, FSEventsEventContext);

 public:
  void init();

  /**
   * @brief This exports a single Callback for INotifyEventType events.
   *
   * @param ec The EventCallback type receives an EventContextRef substruct
   * for the INotifyEventType declared in this EventModule subclass.
   *
   * @return Was the callback successfull.
   */
  Status Callback(const FSEventsEventContextRef ec);
};

/**
 * @brief Each EventModule must register itself so the init method is called.
 *
 * This registers PasswdChangesEventModule into the osquery EventModule
 * pseudo-plugin registry.
 */
REGISTER_EVENTMODULE(PasswdChangesEventModule);

void PasswdChangesEventModule::init() {
  for (const auto& path : kDarwinPasswdPaths) {
    auto mc = FSEventsEventType::createMonitorContext();
    mc->path = path;
    BIND_CALLBACK(Callback, mc);
  }
}

Status PasswdChangesEventModule::Callback(const FSEventsEventContextRef ec) {
  Row r;
  r["action"] = ec->action;
  r["time"] = ec->time_string;
  r["target_path"] = ec->path;
  r["transaction_id"] = boost::lexical_cast<std::string>(ec->fsevent_id);
  if (ec->action != "") {
    add(r, ec->time);
  }
  return Status(0, "OK");
}
}
}
