/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <signal.h>
#include <thread>

#include <boost/asio.hpp>
#include <boost/process.hpp>

#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/tables.h>

#include "osquery/events/darwin/log_events.h"

namespace bp = boost::process;

namespace osquery {

REGISTER(LogEventsEventPublisher,
         "event_publisher",
         "darwin_unified_log_events");

void process_log_stream(LogEventsEventPublisher* publisher) {
  // the stream format is
  //   [{
  //     key: value,
  //     ...
  //   },{
  //     key: value,
  //     ...
  //   },{
  // and so on until the `log` process terminates.
  // this thread just slices the stream into individual
  // strings of entries and passes them to the callback

  std::stringstream buffer;
  std::string line;
  while (std::getline(publisher->child_output, line)) {
    if (line[0] == '[' || line[0] == '}') {
      if (buffer.str().size()) {
        buffer << "}";
        publisher->callback(buffer.str());
      }
      buffer.clear();
      buffer.str("");
      buffer << "{";
    } else {
      buffer << line;
    }
  }
}

void LogEventsEventPublisher::callback(std::string json_string) {
  auto ec = createEventContext();
  ec->json_string = json_string;
  fire(ec);
}

Status LogEventsEventPublisher::setUp() {
  if (child.running()) {
    stop();
  }

  try {
    child = bp::child("/usr/bin/log",
                      "stream",
                      "--style",
                      "json",
                      bp::std_in.close(),
                      bp::std_out > child_output,
                      bp::std_err > bp::null);

    reading_thread = std::thread(process_log_stream, this);

    return Status(0, "OK");

  } catch (std::exception& e) {
    LOG(ERROR) << "Exception when setting up log monitoring process: "
               << e.what();
  }

  return Status(1, "Error starting child process and monitoring thread");
}

Status LogEventsEventPublisher::run() {
  return Status(0, "OK");
}

void LogEventsEventPublisher::stop() {
  if (child.running()) {
    kill(child.id(), SIGTERM);
  }

  if (reading_thread.joinable()) {
    reading_thread.join();
  }
}

void LogEventsEventPublisher::tearDown() {
  stop();
}

} // namespace osquery
