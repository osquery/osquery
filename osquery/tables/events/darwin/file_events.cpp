/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <future>
#include <string>
#include <vector>

#include <osquery/config/config.h>
#include <osquery/core/tables.h>
#include <osquery/events/darwin/fsevents.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/events/event_utils.h>

namespace osquery {

extern const std::set<std::string> kCommonFileColumns;

/**
 * @brief Track time, action changes to /etc/passwd
 *
 * This is mostly an example EventSubscriber implementation.
 */
class FileEventSubscriber : public EventSubscriber<FSEventsEventPublisher> {
 public:
  Status init() override {
    return Status(0);
  }

  /// Walk the configuration's file paths, create subscriptions.
  void configure() override;

  /**
   * @brief This exports a single Callback for INotifyEventPublisher events.
   *
   * @param ec The EventCallback type receives an EventContextRef substruct
   * for the INotifyEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Was the callback successful.
   */
  Status Callback(const FSEventsEventContextRef& ec,
                  const FSEventsSubscriptionContextRef& sc);
};

/**
 * @brief Each EventSubscriber must register itself so the init method is
 *called.
 *
 * This registers FileEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(FileEventSubscriber, "event_subscriber", "file_events");

void FileEventSubscriber::configure() {
  // Clear all paths from FSEvents.
  // There may be a better way to find the set intersection/difference.
  removeSubscriptions();

  Config::get().files([this](const std::string& category,
                             const std::vector<std::string>& files) {
    for (const auto& file : files) {
      VLOG(1) << "Added file event listener to: " << file;
      auto sc = createSubscriptionContext();
      sc->path = file;
      sc->category = category;
      subscribe(&FileEventSubscriber::Callback, sc);
    }
  });
}

Status FileEventSubscriber::Callback(const FSEventsEventContextRef& ec,
                                     const FSEventsSubscriptionContextRef& sc) {
  if (ec->action.empty()) {
    return Status(0);
  }

  // Need to call configure on the publisher, not the subscriber
  if (ec->fsevent_flags & kFSEventStreamEventFlagMount) {
    // Should we add listening to the mount point
    auto subscriber = ([this, &ec]() {
      auto msc = createSubscriptionContext();
      msc->path = ec->path + "/*";
      msc->category = "tmp";
      return subscribe(&FileEventSubscriber::Callback, msc);
    });
    std::packaged_task<void()> task(std::move(subscriber));
    auto result = task.get_future();
    std::thread(std::move(task)).detach();
  }

  Row r;
  r["action"] = ec->action;
  r["target_path"] = ec->path;
  r["category"] = sc->category;
  r["transaction_id"] = INTEGER(ec->transaction_id);

  // Add hashing and 'join' against the file table for stat-information.
  decorateFileEvent(
      ec->path, (ec->action == "CREATED" || ec->action == "UPDATED"), r);

  add(r);
  return Status::success();
}
}
