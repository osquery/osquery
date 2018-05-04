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
CLI_FLAG(uint32, ioservice_subordinates, 1, "IOService subordinate threads");

void IOServiceRunner::start() {
  boost::asio::io_service::work work(IOService::get());

  std::vector<std::shared_ptr<std::thread>> sub_thrs;
  for (auto count = 0U; count < FLAGS_ioservice_subordinates; ++count) {
    auto sub_thr = std::make_shared<std::thread>(
        boost::bind(&IOServiceRunner::subordinates, this));
    sub_thrs.push_back(sub_thr);
  }

  runLoop();

  for (auto& thr : sub_thrs) {
    thr->join();
  }
}

void IOServiceRunner::stop() {
  IOService::get().stop();
}

void IOServiceRunner::runLoop() {
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

void IOServiceRunner::subordinates() {
  LOG(INFO) << "IOServiceRunner subordinate started";
  runLoop();
  LOG(INFO) << "IOServiceRunner subordinate stopped";
}

void startIOService() {
// Windows service needs notifications that threads should die: #4235
#ifdef WIN32
  boost::asio::detail::win_thread::set_terminate_threads(true);
#endif

  Dispatcher::addService(std::make_shared<IOServiceRunner>());
}
} // namespace osquery
