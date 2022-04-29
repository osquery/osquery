/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>

#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/distributed/distributed.h>

#include <osquery/dispatcher/distributed_runner.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/time.h>

namespace osquery {

FLAG(uint64,
     distributed_interval,
     60,
     "Seconds between polling for new queries (default 60)")

DECLARE_bool(disable_distributed);
DECLARE_string(distributed_plugin);

const size_t kDistributedAccelerationInterval = 5;

void DistributedRunner::start() {
  auto dist = Distributed();
  while (!interrupted()) {
    dist.pullUpdates();
    dist.runQueries();

    std::string accelerate_checkins_expire_str = "-1";
    Status status = getDatabaseValue(kPersistentSettings,
                                     "distributed_accelerate_checkins_expire",
                                     accelerate_checkins_expire_str);
    if (!status.ok() || getUnixTime() > tryTo<unsigned long int>(
                                            accelerate_checkins_expire_str, 10)
                                            .takeOr(0ul)) {
      pause(std::chrono::seconds(FLAGS_distributed_interval));
    } else {
      pause(std::chrono::seconds(kDistributedAccelerationInterval));
    }
  }
}

Status startDistributed() {
  if (!FLAGS_disable_distributed) {
    Dispatcher::addService(std::make_shared<DistributedRunner>());
    return Status::success();
  } else {
    return Status(1, "Distributed query service not enabled.");
  }
}
} // namespace osquery
