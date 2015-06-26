/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/events/kernel/circular_queue_user.h"

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

namespace osquery {

CQueue::CQueue(size_t size) {
  buffer_ = NULL;
  size_ = 0;
  max_read_ = NULL;
  read_ = NULL;
  fd_ = -1;

  const char *filename = "/dev/osquery";
  osquery_buf_allocate_args_t alloc;
  alloc.size = size;
  alloc.buffer = NULL;

  fd_ = open(filename, O_RDWR);
  if (fd_ < 0) {
    throw CQueueException("Could not open character device.");
  }

  if (ioctl(fd_, OSQUERY_IOCTL_BUF_ALLOCATE, &alloc)) {
    throw CQueueException("Could not allocate shared buffer.");
  }

  buffer_ = (uint8_t *)alloc.buffer;
  size_ = size;
  read_ = (uint8_t *)alloc.buffer;
  max_read_ = (uint8_t *)alloc.buffer;
}

CQueue::~CQueue() {
  if (fd_ >= 0) {
    close(fd_);
    fd_ = -1;
  }
}

void CQueue::subscribe(osquery_event_t event) {
  osquery_subscription_args_t sub;
  sub.event = event;
  sub.subscribe = 1;

  if (ioctl(fd_, OSQUERY_IOCTL_SUBSCRIPTION, &sub)) {
    throw CQueueException("Could not subscribe to event.");
  }
}

osquery_event_t CQueue::dequeue(void **event) {
  if (read_ == max_read_) {
    return (osquery_event_t)0;
  }
  osquery_data_header_t *header = (osquery_data_header_t *)read_;
  if (header->event == END_OF_BUFFER_EVENT) {
    read_ = buffer_;
    if (read_ == max_read_) {
      return (osquery_event_t)0;
    }
  }
  header = (osquery_data_header_t *)read_;
  if (header->event != END_OF_BUFFER_EVENT) {
    size_t size = osquery_sizeof_event(header->event)
      + sizeof(osquery_data_header_t);
    read_ = (read_ + size - buffer_) % size_ + buffer_;
  }


  *event = (void *)(header + 1);
  return header->event;
}

// return positive idicates drop, 0 is all good in the hood.
// options are listed in kernel feeds.  primarily OSQUERY_NO_BLOCK.
int CQueue::kernelSync(int options) {
  osquery_buf_sync_args_t sync;
  sync.read_offset = read_ - buffer_;
  sync.options = options;

  int err = 0;
  if ((err = ioctl(fd_, OSQUERY_IOCTL_BUF_SYNC, &sync))) {
    throw CQueueException("Could not sync buffer with kernel properly.");
  }
  uint8_t *new_max_read =  sync.max_read_offset + buffer_;
  max_read_ = new_max_read;
  if (err) {
    read_ = max_read_;
  }

  return sync.drops;
}

}  // namespace osquery
