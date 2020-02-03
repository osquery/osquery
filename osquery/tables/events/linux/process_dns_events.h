/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/events/linux/processdnseventspublisher.h>

namespace osquery {

class ProcessDNSEventsSubscriber final
    : public EventSubscriber<ProcessDNSEventsPublisher> {
 public:
  Status init() override;
  Status Callback(const ECRef& ec, const SCRef& sc);
};
} // namespace osquery
