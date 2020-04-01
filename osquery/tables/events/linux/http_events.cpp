/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/tables.h>
#include <osquery/registry_factory.h>

#include "osquery/events/linux/http_event_publisher.h"

namespace osquery {

class HTTPLookupEventSubscriber
    : public EventSubscriber<HTTPLookupEventPublisher> {
 public:
  Status init() override {
    HTTPLookupSubscriptionContextRef sc = createSubscriptionContext();
    subscribe(&HTTPLookupEventSubscriber::Callback, sc);
    return Status(0, "OK");
  }

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(HTTPLookupEventSubscriber, "event_subscriber", "http_events");

Status HTTPLookupEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  r["time"] = BIGINT(ec->time);
  r["method"] = ec->method;
  r["protocol"] = ec->protocol;
  r["local"] = ec->local;
  r["remote"] = ec->remote;
  r["s_port"] = BIGINT(ec->s_port);
  r["d_port"] = BIGINT(ec->d_port);
  r["host"] = ec->host;
  r["port"] = INTEGER(ec->host_port);
  r["uri"] = ec->uri;
  r["content_type"] = ec->content_type;
  r["user_agent"] = ec->user_agent;
  r["ja3"] = ec->ja3;
  r["ja3_fingerprint"] = ec->ja3_fingerprint;
  r["other_headers"] = ec->other_headers;
    
  add(r);
  return Status(0, "OK");
}
} // namespace osquery
