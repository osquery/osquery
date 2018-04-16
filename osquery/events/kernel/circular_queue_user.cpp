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

#include "osquery/events/kernel/circular_queue_user.h"

namespace osquery {

CQueue::CQueue(const std::string &device, size_t size) {
  osquery_buf_allocate_args_t alloc;
  alloc.size = size;
  alloc.buffer = nullptr;
  alloc.version = OSQUERY_KERNEL_COMM_VERSION;

  fd_ = open(device.c_str(), O_RDWR);
  if (fd_ < 0) {
    throw CQueueException("Could not open character device");
  }

  if (ioctl(fd_, OSQUERY_IOCTL_BUF_ALLOCATE, &alloc)) {
    throw CQueueException("Could not allocate shared buffer");
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
    throw CQueueException("Could not subscribe to event");
  }
}

osquery_event_t CQueue::dequeue(CQueue::event **event) {
  if (read_ == max_read_ || event == nullptr) {
    return (osquery_event_t)0;
  }
  osquery_data_header_t *header = (osquery_data_header_t *)read_;
  if (read_ + sizeof(osquery_data_header_t) > buffer_ + size_ ||
      header->event == END_OF_BUFFER_EVENT) {
    read_ = buffer_;
    if (read_ == max_read_) {
      return (osquery_event_t)0;
    }
  }
  header = (osquery_data_header_t *)read_;
  if (header->event != END_OF_BUFFER_EVENT) {
    size_t size = header->size + sizeof(osquery_data_header_t);
    read_ = (read_ + size - buffer_) % size_ + buffer_;
  }

  *event = (CQueue::event *)&(header->size);
  return header->event;
}

int CQueue::kernelSync(int options) {
  // A positive return indicates drops, 0 is all good in the hood.
  // Options are listed in kernel feeds; primarily OSQUERY_OPTIONS_NO_BLOCK.
  osquery_buf_sync_args_t sync;
  sync.read_offset = read_ - buffer_;
  sync.options = options;

  int err{0};
  err = ioctl(fd_, OSQUERY_IOCTL_BUF_SYNC, &sync);
  uint8_t *new_max_read = sync.max_read_offset + buffer_;
  max_read_ = new_max_read;
  if (err) {
    read_ = max_read_;
    throw CQueueException("Could not sync buffer with kernel properly");
  }

  return sync.drops;
}

} // namespace osquery
