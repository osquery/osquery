/*
 *  Copyright (c) 2014-present, Facebook, Inc.
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
#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/events/darwin/openbsm.h"
#include "osquery/tables/events/event_utils.h"

namespace osquery {

class OpenBSMSubscriber : public EventSubscriber<OpenBSMEventPublisher> {
 public:
  Status init() override {
    return Status(0);
  }

  void configure() override;

  /**
   * @brief This exports a single Callback for OpenBSM events.
   *
   * @param ec The EventCallback type receives an EventContextRef substruct
   * for the OpenBSMEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Was the callback successful.
   */
  Status Callback(const OpenBSMEventContextRef& ec,
                  const OpenBSMSubscriptionContextRef& sc);
};

/**
 * @brief Each EventSubscriber must register itself so the init method is
 *called.
 *
 * This registers OpenBSMSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(OpenBSMSubscriber, "event_subscriber", "process_execution_events");

void OpenBSMSubscriber::configure() {
      auto sc = createSubscriptionContext();
      sc->event_id = 23;
      subscribe(&OpenBSMSubscriber::Callback, sc);
}

Status OpenBSMSubscriber::Callback(const OpenBSMEventContextRef& ec,
                                   const OpenBSMSubscriptionContextRef& sc) {

  Row r;
  r["path"] = ec->event_details["path"];
  r["pid"] = ec->event_details["pid"];
  r["args"] = ec->event_details["args"];
  r["time"] = ec->event_details["time"];
  r["euid"] = ec->event_details["euid"];
  r["ruid"] = ec->event_details["ruid"];
  r["status"] = ec->event_details["status"];

  add(r);
  return Status(0, "OK");
}
}
