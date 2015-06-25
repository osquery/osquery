/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <sys/ioccom.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Event feed types
//

typedef enum osquery_event {
  END_OF_BUFFER_EVENT = 0,  // Null event used to signal the end of the buffer.

#ifdef DEBUG
  OSQUERY_TEST_EVENT_0,
  OSQUERY_TEST_EVENT_1,
#endif // DEBUG

  OSQUERY_EVENT_NUM_EVENTS  // Number of different event types.
} osquery_event_t;

#ifdef DEBUG
typedef struct test_event_0 {
  uint32_t my_num;
  char my_str[64];
} test_event_0_data_t;

typedef struct test_event_1 {
  uint32_t my_num;
  char my_str[33];
} test_event_1_data_t;
#endif // DEBUG

static inline size_t osquery_sizeof_event(osquery_event_t e) {
  switch (e) {
#ifdef DEBUG
    case OSQUERY_TEST_EVENT_0:
      return sizeof(test_event_0_data_t);
    case OSQUERY_TEST_EVENT_1:
      return sizeof(test_event_1_data_t);
#endif // DEBUG
    default:
      return -1;
  }
}

//
// Header for event data.
//

typedef struct osquery_data_header {
  osquery_event_t event;
  int finished;
} osquery_data_header_t;

//
// IOCTL messages
//

typedef struct osquery_subscription_args {
  osquery_event_t event;
  int subscribe;
} osquery_subscription_args_t;

typedef struct osquery_buf_update_args {
  size_t read_offset;      // Offset of daemon read pointer.
  size_t max_read_offset;  // (Output) Offset of max_read pointer.
  int drops;               // (Output) Number of drops or negative on overflow.
} osquery_buf_update_args_t;

typedef struct osquery_buf_allocate_args {
  size_t size;      // Size of shared user kernel buffer.
  void *buffer;     // (Output) Pointer to buffer location.
} osquery_buf_allocate_args_t;

// TODO: Choose a proper IOCTL num.
#define OSQUERY_IOCTL_NUM 0xFA
#define OSQUERY_IOCTL_SUBSCRIPTION \
  _IOW(OSQUERY_IOCTL_NUM, 0x1, osquery_subscription_args_t)
#define OSQUERY_IOCTL_BUF_UPDATE \
  _IOWR(OSQUERY_IOCTL_NUM, 0x2, osquery_buf_update_args_t)
#define OSQUERY_IOCTL_BUF_ALLOCATE \
  _IOWR(OSQUERY_IOCTL_NUM, 0x3, osquery_buf_allocate_args_t)

#ifdef DEBUG
#define OSQUERY_IOCTL_TEST \
  _IOW(OSQUERY_IOCTL_NUM, 0x4, int)
#endif // DEBUG

#ifdef __cplusplus
}  // end extern "c"
#endif

