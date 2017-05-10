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

#include "kernel/darwin/iokit/driver.h"

#include <IOKit/IODataQueueShared.h>
#include <kern/clock.h>
#include <sys/proc.h>
#include <sys/vnode.h>

#include "kernel/darwin/iokit/public.h"
#include "kernel/darwin/iokit/logging.h"

// This required macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires.
OSDefineMetaClassAndStructors(com_facebook_iokit_osquery, IOService)

// Define the driver's superclass.
#define super IOService

// Paths to monitor. File modifications in any subdirectory will be logged.
const char *const monitored_paths[] = { "/Users", "/Library", "/Volume",
                                        "/System" };

// Number of active listener instances.
SInt32 listener_instances = 0;

static void SendMessageToDaemon(
    IOSharedDataQueue *data_queue, kauth_cred_t credential,
    kauth_action_t action, uintptr_t arg0, uintptr_t arg1) {
  kernel_osquery_message_t message = {0};
  clock_get_calendar_microtime(
      &(message.time_secs), &(message.time_microsecs));
  message.action = action;
  message.pid = proc_selfpid();
  message.ppid = proc_selfppid();
  message.uid = kauth_cred_getuid(credential);
  message.ruid = kauth_cred_getruid(credential);
  proc_selfname(message.proc_name, MAXCOMLEN + 1);
  if ((message.action == KAUTH_FILEOP_RENAME ||
       message.action == KAUTH_FILEOP_LINK ||
       message.action == KAUTH_FILEOP_EXCHANGE) &&
      arg0) {
    strlcpy(message.from_path, reinterpret_cast<const char*>(arg0),
            MAX_PATH_LEN + 1);
  }
  if (arg1) {
    strlcpy(message.to_path, reinterpret_cast<const char*>(arg1),
            MAX_PATH_LEN + 1);
  }
  if (data_queue) {
    data_queue->enqueue(&message, sizeof(message));
  }
}

// The kernel ignores the return value of a file operation scope listener.
// However, it is recommended that the function always return
// KAUTH_RESULT_DEFER.
static int FileOpScopeListener(
    kauth_cred_t credential, void *data_queue, kauth_action_t action,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3) {
  OSIncrementAtomic(&listener_instances);
  bool valid_event = true;
  // Ignore noisy events.
  if (action == KAUTH_FILEOP_OPEN ||
      (action == KAUTH_FILEOP_CLOSE && !(arg2 & KAUTH_FILEOP_CLOSE_MODIFIED))) {
    valid_event = false;
  }
  if (action == KAUTH_FILEOP_EXEC && proc_selfpid() == 1)
    valid_event = false;
  if (valid_event && action != KAUTH_FILEOP_EXEC) {
    valid_event = false;
    // Check whether the file path matches one of the monitored paths.
    for (const auto& path : monitored_paths) {
      if (strprefix(reinterpret_cast<const char *>(arg1), path)) {
        valid_event = true;
        break;
      }
    }
  }
  if (valid_event) {
    SendMessageToDaemon(
        reinterpret_cast<IOSharedDataQueue *>(data_queue), credential, action,
        arg0, arg1);
  }
  OSDecrementAtomic(&listener_instances);
  return KAUTH_RESULT_DEFER;
}

bool OsqueryDriverClassName::start(IOService *provider) {
  bool result = super::start(provider);
  LOGD("Starting.");
  // Create and initialize an IODataQueue object.
  data_queue_ = IOSharedDataQueue::withCapacity(
      kQueueEventCapacity
      * (sizeof(kernel_osquery_message_t) + DATA_QUEUE_ENTRY_HEADER_SIZE));
  if (data_queue_ == nullptr) {
    return false;
  }
  // Returns a pointer to an IOMemoryDescriptor that refers to the buffer inside
  // our IODataQueue object.
  memory_to_share_ = data_queue_->getMemoryDescriptor();
  if (memory_to_share_ == nullptr) {
    data_queue_->release();
    data_queue_ = nullptr;
    return false;
  }
  file_op_listener_ = kauth_listen_scope(
      KAUTH_SCOPE_FILEOP, FileOpScopeListener, data_queue_);
  if (file_op_listener_ == nullptr) {
    memory_to_share_->release();
    memory_to_share_ = nullptr;
    data_queue_->release();
    data_queue_ = nullptr;
    return false;
  }
  registerService();
  return result;
}

void OsqueryDriverClassName::stop(IOService *provider) {
  LOGD("Stopping.");
  kernel_osquery_message_t message = {0};
  message.action = kStopParserThread;
  if (data_queue_ == nullptr
      || !(data_queue_->enqueue(&message, sizeof(message)))) {
    LOGD("Failed to send stop message to daemon.");
  }
  if (file_op_listener_) {
    kauth_unlisten_scope(file_op_listener_);
    file_op_listener_ = nullptr;
  }
  while (listener_instances > 0) {
    LOGD("Waiting for listener instances to complete.");
    IOSleep(500 /* milliseconds */);
  }
  if (memory_to_share_) {
    memory_to_share_->release();
    memory_to_share_ = nullptr;
  }
  if (data_queue_) {
    data_queue_->release();
    data_queue_ = nullptr;
  }
  super::stop(provider);
}

IOReturn OsqueryDriverClassName::SetNotificationPort(mach_port_t port) {
  if (data_queue_ == nullptr) {
    return kIOReturnError;
  }
  data_queue_->setNotificationPort(port);
  return kIOReturnSuccess;
}

IOMemoryDescriptor *OsqueryDriverClassName::GetSharedMemory() {
  return memory_to_share_;
}
