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

#include <boost/asio.hpp>

#include <osquery/dispatcher.h>

namespace osquery {

class IOService {
 public:
  static boost::asio::io_service& get() {
    static boost::asio::io_service instance;
    return instance;
  }
};

/// A Dispatcher service thread runs adhoc io service provider.
class IOServiceRunner : public InternalRunnable {
 public:
  IOServiceRunner() : InternalRunnable("IOServiceRunner") {}

 public:
  /// The Dispatcher thread entry point.
  void start() override;

  /// The Dispatcher interrupt point.
  void stop() override;
};

/// Start IOService
void startIOService();
}
