/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <chrono>

#include <osquery/dispatcher.h>
#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/killswitch/killswitch_refreshable_plugin.h>

namespace osquery {

FLAG(uint32,
     killswitch_refresh_rate,
     10,
     "Refresh rate of killswitch in seconds");

class KillswitchRefresher : public InternalRunnable {
 public:
  KillswitchRefresher(std::chrono::seconds update_interval)
      : InternalRunnable("KillswitchRefreshRunner"),
        update_interval_(update_interval) {}
  /// A simple wait/interruptible lock.
  void start() override {
    while (!interrupted()) {
      pause(std::chrono::milliseconds(update_interval_));
      osquery::Killswitch::get().refresh();
    }
  }

 private:
  const std::chrono::seconds update_interval_;
};

Status KillswitchRefreshablePlugin::setUp() {
  if (FLAGS_killswitch_refresh_rate > 0) {
    Dispatcher::addService(std::make_shared<KillswitchRefresher>(
        std::chrono::seconds(FLAGS_killswitch_refresh_rate)));
  }
  return Status::success();
}

Status KillswitchRefreshablePlugin::call(const PluginRequest& request,
                                         PluginResponse& response) {
  auto action = request.find(Killswitch::action_);
  if (action == request.end()) {
    return Status::failure("Config plugins require an action");
  }

  if (action->second == Killswitch::refresh_) {
    auto result = refresh();
    if (result) {
      return Status::success();
    } else {
      return Status::failure(result.getError().getFullMessageRecursive());
    }
  } else {
    return KillswitchPlugin::call(request, response);
  }
}

} // namespace osquery
