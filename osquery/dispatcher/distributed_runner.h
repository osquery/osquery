/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/dispatcher.h>

namespace osquery {

/// A Dispatcher service thread that implements the distributed query service
class DistributedRunner : public InternalRunnable {
 public:
  virtual ~DistributedRunner() {}
  DistributedRunner() : InternalRunnable("DistributedRunner") {}

 public:
  /// The Dispatcher thread entry point.
  void start() override;
};

Status startDistributed();
} // namespace osquery
