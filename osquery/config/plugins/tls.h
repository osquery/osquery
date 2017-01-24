/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <vector>

#include <osquery/config.h>
#include <osquery/dispatcher.h>

namespace osquery {

class TLSConfigPlugin;

class TLSConfigPlugin : public ConfigPlugin,
                        public std::enable_shared_from_this<TLSConfigPlugin> {
 public:
  Status setUp() override;
  Status genConfig(std::map<std::string, std::string>& config) override;
  static std::atomic<size_t> kCurrentDelay;

 protected:
  /// Calculate the URL once and cache the result.
  std::string uri_;

 private:
  friend class TLSConfigTests;

  void updateDelayPeriod(bool success);
  bool started_thread_{false};
};

class TLSConfigRefreshRunner : public InternalRunnable {
 public:
  /// A simple wait/interruptible lock.
  void start();
};
}
