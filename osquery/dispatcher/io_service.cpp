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

void IOContextRunner::start() {
  while (!interrupted()) {
    try {
      boost::asio::executor_work_guard<boost::asio::io_context::executor_type>
          work = boost::asio::make_work_guard(IOContext::get());
      work.reset();
      return;
    } catch (const std::exception& e) {
      LOG(WARNING) << "IOContextRunner: handler exception: " << e.what();
    } catch (...) {
      LOG(WARNING) << "IOContextRunner: unknown handler exception";
    }
  }
}

void IOContextRunner::stop() {
  IOContext::get().stop();
}

void startIOContext() {
// Windows service needs notifications that threads should die: #4235
#ifdef WIN32
  boost::asio::detail::win_thread::set_terminate_threads(true);
#endif

  Dispatcher::addService(std::make_shared<IOContextRunner>());
}
} // namespace osquery
