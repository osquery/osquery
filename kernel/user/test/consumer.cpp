/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <circular_queue_user.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

#include <stdexcept>
#include <iostream>

static int exit_flag = 0;

void sig_handler(int s){
  printf("Consumer task has finished. Signal %d\n",s);
  
  exit_flag = 1;
}

int main() {
  int drops = 0;
  int reads = 0;
  struct sigaction sigIntHandler;

  sigIntHandler.sa_handler = sig_handler;
  sigemptyset(&sigIntHandler.sa_mask);
  sigIntHandler.sa_flags = 0;

  sigaction(SIGINT, &sigIntHandler, NULL);
  
  try {
  CQueue cqueue(20 * (1<<20));

  test_event_0_data_t *my_event;
  osquery_event_t event;
  void *event_buf = NULL;
  while(!exit_flag) {
    drops += cqueue.kernelSync();
    int max_before_sync = 2000;
    while (max_before_sync > 0 && (event = cqueue.dequeue(&event_buf))) {
      switch (event) {
        case OSQUERY_TEST_EVENT_0:
        case OSQUERY_TEST_EVENT_1:
          // Do something with the event_buf now.
          reads++;
          break;
        default:
          throw std::runtime_error("Uh oh. Unknown event.");
      }
      max_before_sync --;
    }
  }
  } catch (const CQueueException &e) {
    std::cerr << e.what() << std::endl;
  }
  printf("Read %d, entries.\n", reads);
  printf("Dropped %d, entries.\n", drops);

  return 0;
}

