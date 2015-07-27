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

#ifdef __linux__
#include <linux/ioctl.h>
#include <linux/limits.h>

#define MAXPATHLEN PATH_MAX
#else
#include <sys/ioccom.h>
#include <sys/param.h>
#endif

/** @brief Communication version between kernel and daemon.
 *
 *  A daemon may only connect to a kernel with the same communication version.
 *  Bump this number when changing or adding any event structs.
 */
#define OSQUERY_KERNEL_COMMUNICATION_VERSION 3UL
#ifdef KERNEL_TEST
#define OSQUERY_KERNEL_COMM_VERSION \
  (OSQUERY_KERNEL_COMMUNICATION_VERSION | (1UL << 63))
#else
#define OSQUERY_KERNEL_COMM_VERSION OSQUERY_KERNEL_COMMUNICATION_VERSION
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def KERNEL_TEST
 * @brief This gates the testing portions of kernel module.
 *
 * When kernel test is defined two testing events are exposed.  Additionally
 * the character device can be opened multiple times, which allows the use of
 * a reentrant testing IOCTL call that adds test events to the cqueue structure.
 */

//
// Event feed types
//

typedef enum {
  END_OF_BUFFER_EVENT = 0, // Null event used to signal the end of the buffer.
  OSQUERY_NULL_EVENT = 0,
  OSQUERY_PROCESS_EVENT,

#ifdef KERNEL_TEST
  OSQUERY_TEST_EVENT_0,
  OSQUERY_TEST_EVENT_1,
#endif // KERNEL_TEST

  OSQUERY_NUM_EVENTS // Number of different event types.
} osquery_event_t;

typedef struct {
  uint64_t pid;
  uint64_t ppid;
  uint64_t uid;
  uint64_t euid;
  uint64_t gid;
  uint64_t egid;
  uint64_t owner_uid;
  uint64_t owner_gid;
  uint64_t create_time;
  uint64_t access_time;
  uint64_t modify_time;
  uint64_t change_time;
  int mode;
  char path[MAXPATHLEN];
  size_t argv_offset;
  int argc;
  int actual_argc;
  size_t arg_length;
  size_t envv_offset;
  int envc;
  int actual_envc;
  size_t env_length;
  char flexible_data[0]; // Flexible array space.
} osquery_process_event_t;

#ifdef KERNEL_TEST
typedef struct {
  uint32_t my_num;
  char my_str[4096];
} test_event_0_data_t;

typedef struct {
  uint32_t my_num;
  char my_str[33];
} test_event_1_data_t;
#endif // KERNEL_TEST

//
// Header for event data.
//

typedef struct {
  /// Calendar time in seconds since UNIX epoch.
  uint32_t time;
  /// System uptime in seconds.
  uint32_t uptime;
} osquery_event_time_t;

typedef struct {
  osquery_event_t event;
  int finished;
  size_t size; // Should be second to last member of header.
  osquery_event_time_t time; // Should be last member of header.
} osquery_data_header_t;

//
// IOCTL messages
//

typedef struct {
  osquery_event_t event;
  int subscribe;
  void *udata;
} osquery_subscription_args_t;

// Flags for buffer sync options.
#define OSQUERY_DEFAULT 0
#define OSQUERY_NO_BLOCK 1

typedef struct {
  int options;             // Option such as OSQUERY_NO_BLOCK.
  size_t read_offset;      // Offset of daemon read pointer.
  size_t max_read_offset;  // (Output) Offset of max_read pointer.
  int drops;               // (Output) Number of drops or negative on overflow.
} osquery_buf_sync_args_t;

typedef struct {
  size_t size;      // Size of shared user kernel buffer.
  void *buffer;     // (Output) Pointer to buffer location.
  uint64_t version; // osquery kernel communication version.
} osquery_buf_allocate_args_t;

// TODO: Choose a proper IOCTL num.
#define OSQUERY_IOCTL_NUM 0xFA
#define OSQUERY_IOCTL_SUBSCRIPTION \
  _IOW(OSQUERY_IOCTL_NUM, 0x1, osquery_subscription_args_t)
#define OSQUERY_IOCTL_BUF_SYNC \
  _IOWR(OSQUERY_IOCTL_NUM, 0x2, osquery_buf_sync_args_t)
#define OSQUERY_IOCTL_BUF_ALLOCATE \
  _IOWR(OSQUERY_IOCTL_NUM, 0x3, osquery_buf_allocate_args_t)

#ifdef KERNEL_TEST
#define OSQUERY_IOCTL_TEST \
  _IOW(OSQUERY_IOCTL_NUM, 0x4, int)
#endif // KERNEL_TEST

#ifdef __cplusplus
}  // end extern "c"
#endif
