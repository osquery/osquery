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
#include <osquery/events.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/events/kernel.h"

namespace osquery {

class ProcessFileEventSubscriber
    : public EventSubscriber<KernelEventPublisher> {
 public:
  Status init() override;
  /// Walk the configuration's file paths, create subscriptions.
  void configure() override;

  Status Callback(const TypedKernelEventContextRef<osquery_file_event_t> &ec,
                  const KernelSubscriptionContextRef &sc);
};

REGISTER(ProcessFileEventSubscriber, "event_subscriber", "process_file_events");

Status ProcessFileEventSubscriber::init() {
  auto pubref = EventFactory::getEventPublisher("kernel");
  if (pubref == nullptr || pubref->isEnding()) {
    return Status(1, "No kernel event publisher");
  }

  return Status(0);
}

void ProcessFileEventSubscriber::configure() {
  // There may be a better way to find the set intersection/difference.
  removeSubscriptions();

  Config::getInstance().files([this](const std::string &category,
                                     const std::vector<std::string> &files) {
    for (const auto &file : files) {
      auto sc = createSubscriptionContext();
      sc->event_type = OSQUERY_FILE_EVENT;
      osquery_file_event_subscription_t sub = {
          .actions = (osquery_file_action_t)(
              OSQUERY_FILE_ACTION_OPEN | OSQUERY_FILE_ACTION_CLOSE |
              OSQUERY_FILE_ACTION_CLOSE_MODIFIED)};
      auto path = file;
      replaceGlobWildcards(path);
      path = path.substr(0, path.find("*"));
      strncpy(sub.path, path.c_str(), MAXPATHLEN);
      sc->category = category;
      VLOG(1) << "Added process file event listener to: " << path;
      subscribe(&ProcessFileEventSubscriber::Callback, sc);
    }
  });
}

Status ProcessFileEventSubscriber::Callback(
    const TypedKernelEventContextRef<osquery_file_event_t> &ec,
    const KernelSubscriptionContextRef &sc) {
  Row r;
  switch (ec->event.action) {
  case OSQUERY_FILE_ACTION_OPEN:
    r["action"] = "OPEN";
    break;
  case OSQUERY_FILE_ACTION_CLOSE:
    r["action"] = "CLOSE";
    break;
  case OSQUERY_FILE_ACTION_CLOSE_MODIFIED:
    r["action"] = "CLOSE MODIFIED";
    break;
  default:
    r["action"] = "UNKNOWN";
    break;
  }

  r["pid"] = BIGINT(ec->event.pid);
  r["parent"] = BIGINT(ec->event.ppid);
  r["uid"] = BIGINT(ec->event.uid);
  r["euid"] = BIGINT(ec->event.euid);
  r["gid"] = BIGINT(ec->event.gid);
  r["egid"] = BIGINT(ec->event.egid);
  r["owner_uid"] = BIGINT(ec->event.owner_uid);
  r["owner_gid"] = BIGINT(ec->event.owner_gid);
  r["ctime"] = BIGINT(ec->event.change_time);
  r["atime"] = BIGINT(ec->event.access_time);
  r["mtime"] = BIGINT(ec->event.modify_time);
  r["mode"] = BIGINT(ec->event.mode);
  r["path"] = ec->event.path;
  r["uptime"] = BIGINT(ec->uptime);

  add(r);

  return Status(0, "OK");
}

} // namespace osquery
