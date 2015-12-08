/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/events/kernel.h"

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/filesystem.h>

namespace osquery {

class FileAccessEventSubscriber : public EventSubscriber<KernelEventPublisher> {
 public:
  Status init() override;

  Status Callback(const TypedKernelEventContextRef<osquery_file_event_t> &ec);
};

REGISTER(FileAccessEventSubscriber, "event_subscriber", "file_access_events");

Status FileAccessEventSubscriber::init() {
  Config::getInstance().files(
      [this](const std::string &, const std::vector<std::string> &files) {
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
          sc->udata = &sub;
          VLOG(1) << "Added kernel listener to: " << path;

          subscribe(&FileAccessEventSubscriber::Callback, sc);
        }
      });

  return Status(0, "OK");
}

Status FileAccessEventSubscriber::Callback(
    const TypedKernelEventContextRef<osquery_file_event_t> &ec) {
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
  r["create_time"] = BIGINT(ec->event.create_time);
  r["access_time"] = BIGINT(ec->event.access_time);
  r["modify_time"] = BIGINT(ec->event.modify_time);
  r["change_time"] = BIGINT(ec->event.change_time);
  r["mode"] = BIGINT(ec->event.mode);
  r["path"] = ec->event.path;
  r["uptime"] = BIGINT(ec->uptime);

  add(r, ec->time);

  return Status(0, "OK");
}

} // namespace osquery
