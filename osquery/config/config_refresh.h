/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/dispatcher.h>
#include <osquery/utils/expected/expected.h>
#include <osquery/utils/mutex.h>
#include <osquery/utils/status/status.h>

#include <atomic>

namespace osquery {

/**
 * @brief A thread that periodically reloads configuration state.
 *
 * This refresh runner thread can refresh any configuration plugin.
 * It may accelerate the time between checks if the configuration fails to load.
 * For configurations pulled from the network this assures that configuration
 * is fresh when re-attaching.
 */
class ConfigRefreshRunner : public InternalRunnable {
 public:
  ConfigRefreshRunner() : InternalRunnable("ConfigRefreshRunner") {}

  /// A simple wait/interruptible lock.
  void start() override;

  /// Update the refresh rate.
  void setRefresh(size_t refresh_sec);

  /// Inspect the refresh rate.
  size_t getRefresh() const;

  /// Perform a config refresh.
  Status refresh();

 private:
  /// The current refresh rate in seconds.
  std::atomic<size_t> refresh_sec_{0};
  std::atomic<bool> first_{true};

  Mutex config_refresh_mutex_;

 private:
  friend class Config;
};

/**
 * This creates a thread to watch for configuration changes.
 *
 */
Status startAndLoadConfig();
} // namespace osquery
