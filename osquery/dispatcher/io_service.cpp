/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/logger.h>

#include "osquery/dispatcher/io_service.h"

namespace osquery {

void IOServiceRunner::start() {
  boost::asio::io_service::work work(IOService::get());
  for (;;) {
    try {
      IOService::get().run();
      return;
    } catch (const std::exception& e) {
      LOG(WARNING) << "IOServiceRunner: handler exception: " << e.what();
    } catch (...) {
      LOG(WARNING) << "IOServiceRunner: unknown handler exception";
    }
  }
}

void IOServiceRunner::stop() {
  IOService::get().stop();
}

void startIOService() {
  Dispatcher::addService(std::make_shared<IOServiceRunner>());
}
}
