/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include <benchmark/benchmark.h>

#include <osquery/dispatcher.h>

#include "osquery/events/kernel.h"

namespace osquery {

#ifdef KERNEL_TEST

static inline void producerThread(benchmark::State &state) {
  std::unique_ptr<CQueue> queue = nullptr;
  try {
    queue = std::unique_ptr<CQueue>(new CQueue(kKernelDevice, 8 * (1 << 20)));
  } catch (const CQueueException &e) {
    // The device interface cannot be found or cannot be opened.
  }

  osquery_event_t event;
  osquery::CQueue::event *event_buf = nullptr;
  int drops = 0;
  size_t reads0 = 0;
  size_t reads1 = 0;
  size_t syncs = 0;
  int max_before_sync = 0;
  while (state.KeepRunning()) {
    if (queue == nullptr) {
      continue;
    }
    drops += queue->kernelSync(OSQUERY_OPTIONS_NO_BLOCK);
    syncs++;
    max_before_sync = 2000;
    while (max_before_sync > 0 && (event = queue->dequeue(&event_buf))) {
      switch (event) {
      case OSQUERY_TEST_EVENT_0:
        reads0++;
        max_before_sync--;
        break;
      case OSQUERY_TEST_EVENT_1:
        reads1++;
        max_before_sync--;
        break;
      default:
        break;
      }
    }
  }

  state.SetBytesProcessed(reads0 * sizeof(test_event_0_data_t) +
                          reads1 * sizeof(test_event_1_data_t) +
                          (reads0 + reads1) * sizeof(osquery_event_time_t));
  state.SetItemsProcessed(reads0 + reads1);
  auto label = std::string("dropped: ") + std::to_string(drops) + "  syncs: " +
               std::to_string(syncs);
  state.SetLabel(label);
}

static inline void consumerThread(benchmark::State &state) {
  int fd = open(kKernelDevice.c_str(), O_RDWR);
  int type = state.thread_index % 2;
  while (state.KeepRunning()) {
    ioctl(fd, OSQUERY_IOCTL_TEST, &type);
  }
  close(fd);
}

static void CommunicationBenchmark(benchmark::State &state) {
  if (state.thread_index == 0) {
    producerThread(state);
  } else {
    consumerThread(state);
  }
}

BENCHMARK(CommunicationBenchmark)->UseRealTime()->ThreadRange(2, 32);

#endif // KERNEL_TEST
}
