/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/dispatcher/dispatcher.h>

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
