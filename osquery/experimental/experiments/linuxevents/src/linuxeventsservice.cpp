/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "linuxeventsservice.h"

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>

namespace osquery {

CLI_FLAG(uint32,
         experiments_linuxevents_perf_output_size,
         12,
         "Perf ouput size (must be a power of two)");

CLI_FLAG(uint32,
         experiments_linuxevents_circular_buffer_size,
         1000,
         "Size of the circular buffer used by tables to store events");

struct LinuxEventsService::PrivateData final {
  PrivateData(BPFProcessEventsTable& table_) : table(table_) {}
  BPFProcessEventsTable& table;
};

LinuxEventsService::LinuxEventsService(BPFProcessEventsTable& table)
    : InternalRunnable("LinuxEventsService"), d(new PrivateData(table)) {}

LinuxEventsService::~LinuxEventsService() {}

void LinuxEventsService::start() {
  auto linux_events_exp = tob::linuxevents::ILinuxEvents::create(
      FLAGS_experiments_linuxevents_perf_output_size);
  if (!linux_events_exp.succeeded()) {
    LOG(ERROR)
        << "linuxevents experiment: Failed to create the LinuxEvents object: "
        << linux_events_exp.error().message();
    return;
  }

  auto linux_events = linux_events_exp.takeValue();

  while (!interrupted()) {
    tob::linuxevents::ILinuxEvents::ErrorCounters error_counters;
    auto event_list_exp = linux_events->processEvents(error_counters);
    if (!event_list_exp.succeeded()) {
      LOG(ERROR) << event_list_exp.error().message();
      break;
    }

    if (error_counters.lost_event_count != 0) {
      LOG(ERROR) << "linuxevents experiment: Lost events: "
                 << error_counters.lost_event_count;
    }

    if (error_counters.read_error_count != 0) {
      LOG(ERROR) << "linuxevents experiment: Read error count: "
                 << error_counters.read_error_count;
    }

    if (error_counters.invalid_data_count != 0) {
      LOG(ERROR) << "linuxevents experiment: Invalid data: "
                 << error_counters.invalid_data_count;
    }

    error_counters = {};

    auto event_list = event_list_exp.takeValue();
    d->table.addEvents(std::move(event_list));
  }

  VLOG(1) << "linuxevents experiment: Terminating...";
}

void LinuxEventsService::stop() {}
} // namespace osquery
