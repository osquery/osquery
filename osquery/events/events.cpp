/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/eventfactory.h>
#include <osquery/events/events.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/sqlite_util.h>

#include <boost/algorithm/string.hpp>

#include <set>

namespace osquery {

HIDDEN_FLAG(bool,
            events_enforce_denylist,
            false,
            "Enforce denylist for event-based queries");

bool enforceEventsDenylist(const std::string& query) {
  // The only exception for a denylisted query to still run is when this flag
  // is false (the default).
  if (FLAGS_events_enforce_denylist) {
    return true;
  }

  auto tables = QueryPlanner(query).tables();
  if (tables.empty()) {
    return true;
  }

  // Check if the query only operates on event subscribers.
  // If it does, skip the denylist enforcement.
  std::set<std::string> table_set(tables.begin(), tables.end());
  auto event_tables = EventFactory::subscriberNames();

  std::set<std::string> overlap;
  std::set_intersection(table_set.begin(),
                        table_set.end(),
                        event_tables.begin(),
                        event_tables.end(),
                        std::inserter(overlap, overlap.begin()));
  return overlap.size() != table_set.size();
}

void attachEvents() {
  const auto& publishers = RegistryFactory::get().plugins("event_publisher");
  for (const auto& publisher : publishers) {
    EventFactory::registerEventPublisher(publisher.second);
  }

  const auto& subscribers = RegistryFactory::get().plugins("event_subscriber");
  for (const auto& subscriber : subscribers) {
    if (!boost::ends_with(subscriber.first, "_events")) {
      LOG(ERROR) << "Error registering subscriber: " << subscriber.first
                 << ": Must use a '_events' suffix";
      continue;
    }

    auto status = EventFactory::registerEventSubscriber(subscriber.second);
    if (!status.ok()) {
      VLOG(1) << "Skipping subscriber: " << subscriber.first << ": "
              << status.getMessage();
    }
  }

  // Configure the event publishers and subscribers.
  EventFactory::configUpdate();
}

} // namespace osquery
