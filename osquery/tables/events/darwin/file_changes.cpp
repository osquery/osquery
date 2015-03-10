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

#include "osquery/events/darwin/fsevents.h"

namespace osquery {
namespace tables {

/**
 * @brief Track time, action changes to /etc/passwd
 *
 * This is mostly an example EventSubscriber implementation.
 */
class FileChangesEventSubscriber
    : public EventSubscriber<FSEventsEventPublisher> {
  DECLARE_SUBSCRIBER("file_changes");

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
 * This registers FileChangesEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(FileChangesEventSubscriber, "event_subscriber", "file_changes");

Status FileChangesEventSubscriber::init() {
  const auto& file_map = Config::getWatchedFiles();
  for (const auto& element_kv : file_map) {
    for (const auto& file : element_kv.second) {
      VLOG(1) << "Added listener to: " << file;
      auto mc = createSubscriptionContext();
      mc->path = file;
      subscribe(&FileChangesEventSubscriber::Callback, mc,
                (void*)(&element_kv.first));
    }
  }

  return Status(0, "OK");
}

Status FileChangesEventSubscriber::Callback(const FSEventsEventContextRef& ec,
                                            const void* user_data) {
  Row r;
  r["action"] = ec->action;
  r["time"] = ec->time_string;
  r["target_path"] = ec->path;
  if (user_data != nullptr) {
    r["category"] = *(std::string*)user_data;
  } else {
    r["category"] = "Undefined";
  }
  r["transaction_id"] = INTEGER(ec->fsevent_id);
  r["md5"] = hashFromFile(HASH_TYPE_MD5, ec->path);
  r["sha1"] = hashFromFile(HASH_TYPE_SHA1, ec->path);
  r["sha256"] = hashFromFile(HASH_TYPE_SHA256, ec->path);
  if (ec->action != "") {
    add(r, ec->time);
  }
  return Status(0, "OK");
}
}
}
