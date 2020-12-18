/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <osquery/config/config.h>
#include <osquery/core/tables.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/events/linux/inotify.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/events/event_utils.h>

namespace osquery {

/**
 * @brief Track time, action changes to /etc/passwd
 *
 * This is mostly an example EventSubscriber implementation.
 */
class FileEventSubscriber : public EventSubscriber<INotifyEventPublisher> {
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
  Status Callback(const ECRef& ec, const SCRef& sc);
};

/**
 * @brief EventSubscribers must register so their init method is called.
 *
 * This registers FileEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(FileEventSubscriber, "event_subscriber", "file_events");

void FileEventSubscriber::configure() {
  // Clear all monitors from INotify.
  // There may be a better way to find the set intersection/difference.
  removeSubscriptions();

  auto parser = Config::getParser("file_paths");
  if (parser == nullptr) {
    LOG(ERROR) << "No key 'file_paths' found when parsing file events"
                  " subscriber configuration.";
    return;
  }
  auto const& doc = parser->getData().doc();
  auto file_accesses_it = doc.FindMember("file_accesses");
  if (file_accesses_it == doc.MemberEnd()) {
    LOG(ERROR) << "No key 'file_accesses' found when parsing file events"
                  " subscriber configuration.";
    return;
  }
  auto& accesses = file_accesses_it->value;
  if (accesses.GetType() != rapidjson::kArrayType) {
    LOG(ERROR) << "Wrong type found for file_accesses when parsing file events"
                  " subscriber configuration. Found ("
               << accesses.GetType()
               << "),"
                  " expected array ("
               << rapidjson::kArrayType << ").";
    return;
  }
  Config::get().files([this, &accesses](const std::string& category,
                                        const std::vector<std::string>& files) {
    for (const auto& file : files) {
      VLOG(1) << "Added file event listener to: " << file;
      auto sc = createSubscriptionContext();
      // Use the filesystem globbing pattern to determine recursiveness.
      sc->recursive = 0;
      sc->opath = sc->path = file;
      sc->mask = kFileDefaultMasks;

      for (const auto& item : accesses.GetArray()) {
        if (item.GetString() == category) {
          sc->mask |= kFileAccessMasks;
          break;
        }
      }
      sc->category = category;
      subscribe(&FileEventSubscriber::Callback, sc);
    }
  });
}

Status FileEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  if (ec->action.empty()) {
    return Status(0);
  }

  Row r;
  r["action"] = ec->action;
  r["target_path"] = ec->path;
  r["category"] = sc->category;
  r["transaction_id"] = INTEGER(ec->event->cookie);

  if ((sc->mask & kFileAccessMasks) != kFileAccessMasks) {
    // Add hashing and 'join' against the file table for stat-information.
    decorateFileEvent(
        ec->path, (ec->action == "CREATED" || ec->action == "UPDATED"), r);
  } else {
    // The access event on Linux would generate additional events if hashed.
    decorateFileEvent(ec->path, false, r);
  }

  // A callback is somewhat useless unless it changes the EventSubscriber
  // state or calls `add` to store a marked up event.
  add(r);
  return Status::success();
}
} // namespace osquery
