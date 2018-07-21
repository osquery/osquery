/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <boost/asio.hpp>

#include <osquery/dispatcher.h>

namespace osquery {

class IOContext {
 public:
  static boost::asio::io_context& get() {
    static boost::asio::io_context instance;
    return instance;
  }
};

/// A Dispatcher service thread runs adhoc io service provider.
class IOContextRunner : public InternalRunnable {
 public:
  IOContextRunner() : InternalRunnable("IOContextRunner") {}

 public:
  /// The Dispatcher thread entry point.
  void start() override;

  /// The Dispatcher interrupt point.
  void stop() override;
};

/// Start IOService
void startIOContext();
} // namespace osquery
