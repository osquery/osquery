/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/logger.h>

#include "osquery/dispatcher/io_service.h"

namespace osquery {

void IOServiceRunner::start() {
  setThreadName(name());
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
} // namespace osquery
