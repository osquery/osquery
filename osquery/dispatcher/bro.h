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

#include <osquery/dispatcher.h>

namespace osquery {

/// A Dispatcher service thread that implements the bro service
class BroRunner : public InternalRunnable {
 public:
  virtual ~BroRunner() {}
  BroRunner() {}

 public:
  /// The Dispatcher thread entry point.
  void start();
};

Status startBro();
}
