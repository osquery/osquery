/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <Availability.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <os/availability.h>

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/events.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

REGISTER(ESProcessFileEventSubscriber,
         "event_subscriber",
         "es_process_file_events");

Status ESProcessFileEventSubscriber::init() {
  if (__builtin_available(macos 10.15, *)) {
    auto sc = createSubscriptionContext();

    sc->es_file_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_CREATE);
    sc->es_file_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_RENAME);
    sc->es_file_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_WRITE);
    sc->es_file_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_TRUNCATE);

    subscribe(&ESProcessFileEventSubscriber::Callback, sc);

    return Status::success();
  } else {
    return Status::failure(1, "Only available on macOS 10.15 and higher");
  }
}

Status ESProcessFileEventSubscriber::Callback(
    const EndpointSecurityFileEventContextRef& ec,
    const EndpointSecurityFileSubscriptionContextRef& sc) {
  Row r;

  r["version"] = INTEGER(ec->version);
  r["seq_num"] = BIGINT(ec->seq_num);
  r["global_seq_num"] = BIGINT(ec->global_seq_num);

  r["event_type"] = ec->event_type;

  r["pid"] = BIGINT(ec->pid);
  r["parent"] = BIGINT(ec->parent);

  r["path"] = ec->path;

  r["filename"] = ec->filename;

  r["dest_filename"] = ec->dest_filename;

  sc->row_list = {r};
  if (!sc->row_list.empty()) {
    addBatch(sc->row_list);
  }

  return Status::success();
}

} // namespace osquery
