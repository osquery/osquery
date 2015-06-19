/*
 *  Copyright (c) 2015, Google, Inc.
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sys/types.h>

#define MAX_PATH_LEN 1024
#ifndef MAXCOMLEN
#define MAXCOMLEN 16
#endif

// OSQuery message struct used for kernel mode to user mode communications.
typedef struct {
  unsigned long time_secs;  // NOLINT
  unsigned time_microsecs;
  // kauth action type.
  int action;
  uid_t uid;
  uid_t ruid;
  int pid;
  int ppid;
  char proc_name[MAXCOMLEN + 1];
  char from_path[MAX_PATH_LEN + 1];
  char to_path[MAX_PATH_LEN + 1];
} kernel_osquery_message_t;

enum { kQueueEventCapacity = 1000 };
enum { kStopParserThread = 0xFFFFFFFF };
