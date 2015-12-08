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
#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/hash.h>

#include "osquery/events/linux/inotify.h"

namespace osquery {

/**
 * @brief Track time, action changes to /etc/passwd
 *
 * This is mostly an example EventSubscriber implementation.
 */
class FileEventSubscriber : public EventSubscriber<INotifyEventPublisher> {
 public:
  Status init() override;

  /**
   * @brief This exports a single Callback for INotifyEventPublisher events.
   *
   * @param ec The EventCallback type receives an EventContextRef substruct
   * for the INotifyEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Was the callback successful.
   */
  Status Callback(const ECRef& ec, const SCRef& sc);
};

/**
 * @brief Each EventSubscriber must register itself so the init method is
 *called.
 *
 * This registers FileEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(FileEventSubscriber, "event_subscriber", "file_events");

Status FileEventSubscriber::init() {
  Config::getInstance().files([this](const std::string& category,
                                     const std::vector<std::string>& files) {
    for (const auto& file : files) {
      VLOG(1) << "Added listener to: " << file;
      auto sc = createSubscriptionContext();
      // Use the filesystem globbing pattern to determine recursiveness.
      sc->recursive = 0;
      sc->path = file;
      sc->mask = IN_ATTRIB | IN_MODIFY | IN_DELETE | IN_CREATE;
      sc->category = category;
      subscribe(&FileEventSubscriber::Callback, sc);
    }
  });

  return Status(0, "OK");
}

Status FileEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  r["action"] = ec->action;
  r["target_path"] = ec->path;
  r["category"] = sc->category;
  r["transaction_id"] = INTEGER(ec->event->cookie);

  if (ec->action == "CREATED" || ec->action == "UPDATED") {
    r["md5"] = hashFromFile(HASH_TYPE_MD5, ec->path);
    r["sha1"] = hashFromFile(HASH_TYPE_SHA1, ec->path);
    r["sha256"] = hashFromFile(HASH_TYPE_SHA256, ec->path);
  }

  if (ec->action != "" && ec->action != "OPENED") {
    // A callback is somewhat useless unless it changes the EventSubscriber
    // state or calls `add` to store a marked up event.
    add(r, ec->time);
  }
  return Status(0, "OK");
}
}
