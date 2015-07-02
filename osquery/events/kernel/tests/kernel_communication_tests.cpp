/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/dispatcher/dispatcher.h"
#include "osquery/events/kernel/circular_queue_user.h"

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <gtest/gtest.h>

#include <boost/make_shared.hpp>

namespace osquery {

class KernelCommunicationTests : public testing::Test {};

#ifdef KERNEL_TEST
class KernelProducerRunnable : public InternalRunnable {
 public:
  explicit KernelProducerRunnable(int events_to_produce, int event_type)
    : events_to_produce_(events_to_produce),
      event_type_(event_type) {}
  virtual void start() {
    const char *filename = "/dev/osquery";
    int fd = open(filename, O_RDWR);
    if (fd >= 0) {
      for (uint32_t i = 0; i < events_to_produce_; i ++) {
        ioctl(fd, OSQUERY_IOCTL_TEST, &event_type_);
      }

      close(fd);
    }
  }

 private:
  int events_to_produce_;
  int event_type_;
};

TEST_F(KernelCommunicationTests, test_communication) {
  int num_threads = 20;
  int events_per_thread = 100000;
  int drops = 0;
  int reads = 0;

  CQueue queue(8 * (1 << 20));

  auto& dispatcher = Dispatcher::instance();

  for (int c = 0; c < num_threads; ++c) {
    dispatcher.add(
        OSQUERY_THRIFT_POINTER::make_shared<KernelProducerRunnable>(
          events_per_thread, c % 2));
  }

  osquery_event_t event;
  void *event_buf = nullptr;
  int tasks = 0;
  do {
    tasks = dispatcher.totalTaskCount();
    drops += queue.kernelSync(OSQUERY_NO_BLOCK);
    int max_before_sync = 2000;
    while (max_before_sync > 0 && (event = queue.dequeue(&event_buf))) {
      switch (event) {
        case OSQUERY_TEST_EVENT_0:
        case OSQUERY_TEST_EVENT_1:
          reads++;
          break;
        default:
          throw std::runtime_error("Uh oh. Unknown event.");
      }
      max_before_sync --;
    }
  } while (tasks > 0);

  EXPECT_EQ(num_threads * events_per_thread, reads + drops);
}
#endif // KERNEL_TEST
}
