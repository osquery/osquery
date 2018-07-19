/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>

#include "osquery/tables/events/windows/ntfs_file_events.h"

namespace osquery {
REGISTER(NTFSEventSubscriber, "event_subscriber", "ntfs_file_events");

struct NTFSEventSubscriber::PrivateData final {
  NTFSEventSubscriptionContextRef subscription_context;
};

NTFSEventSubscriber::NTFSEventSubscriber() : d(new PrivateData) {}

NTFSEventSubscriber::~NTFSEventSubscriber() {}

Status NTFSEventSubscriber::init() {
  d->subscription_context = createSubscriptionContext();
  subscribe(&NTFSEventSubscriber::Callback, d->subscription_context);

  return Status(0);
}

void NTFSEventSubscriber::configure() {}

Status NTFSEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  // TODO(alessandro): remove this
  std::stringstream path_list;
  path_list << "New events: ";

  for (const auto& p : ec->ref_to_path_map) {
    const auto& ref = p.first;
    const auto& path = p.second;

    path_list << path << ", ";
  }

  path_list << std::endl;
  std::cout << path_list.str();

  std::vector<Row> emitted_row_list;
  addBatch(emitted_row_list);

  return Status(0);
}
} // namespace osquery
