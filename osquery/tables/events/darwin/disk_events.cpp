/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <boost/lexical_cast.hpp>

#include <osquery/events.h>
#include <osquery/events/darwin/diskarbitration.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/tables.h>


namespace osquery {

class DiskEventSubscriber
    : public EventSubscriber<DiskArbitrationEventPublisher> {
 public:
  Status init() override;

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(DiskEventSubscriber, "event_subscriber", "disk_events");

Status DiskEventSubscriber::init() {
  auto subscription = createSubscriptionContext();
  // Don't want physical disk events
  subscription->physical_disks = false;

  subscribe(&DiskEventSubscriber::Callback, subscription);
  return Status::success();
}

Status DiskEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  r["action"] = ec->action;
  r["path"] = ec->path;
  r["name"] = ec->name;
  r["device"] = ec->device;
  r["uuid"] = ec->uuid;
  r["size"] = ec->size;
  r["ejectable"] = ec->ejectable;
  r["mountable"] = ec->mountable;
  r["writable"] = ec->writable;
  r["content"] = ec->content;
  r["media_name"] = ec->media_name;
  r["vendor"] = ec->vendor;
  r["filesystem"] = ec->filesystem;
  r["checksum"] = ec->checksum;

  EventTime et = ec->time;
  if (ec->action == "add") {
    // Disk appearance time may be used in the future.
    boost::conversion::try_lexical_convert(ec->disk_appearance_time, et);
  }

  add(r);
  return Status::success();
}
}
