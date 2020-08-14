/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/system/linux/cpu.h>
#include <osquery/utils/system/linux/perf_event/perf_event.h>

#include <osquery/logger/logger.h>

#include <boost/io/detail/quoted_manip.hpp>

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#include <unistd.h>

#include <utility>

namespace osquery {
namespace ebpf {

template <typename MessageType>
PerfOutput<MessageType>::~PerfOutput() {
  forceUnload();
}

template <typename MessageType>
PerfOutput<MessageType>::PerfOutput(PerfOutput&& other)
    : size_(other.size_), fd_(other.fd_), data_ptr_(other.data_ptr_) {
  other.fd_ = -1;
  other.data_ptr_ = nullptr;
}

template <typename MessageType>
PerfOutput<MessageType>& PerfOutput<MessageType>::operator=(
    PerfOutput&& other) {
  std::swap(size_, other.size_);
  std::swap(fd_, other.fd_);
  std::swap(data_ptr_, other.data_ptr_);
  return *this;
}

template <typename MessageType>
Expected<PerfOutput<MessageType>, PerfOutputError>
PerfOutput<MessageType>::load(std::size_t const cpu, std::size_t const size) {
  auto instance = PerfOutput<MessageType>{};
  instance.size_ = size;

  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(struct perf_event_attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.size = sizeof(struct perf_event_attr);
  attr.config = PERF_COUNT_SW_BPF_OUTPUT;
  attr.sample_period = 1;
  attr.sample_type = PERF_SAMPLE_RAW;
  attr.wakeup_events = 1;
  attr.disabled = 1;

  pid_t const pid = -1;
  int const group_fd = -1;
  unsigned long const flags = 0;
  auto exp_fd = perf_event_open::syscall(
      &attr, pid, static_cast<int>(cpu), group_fd, flags);
  if (exp_fd.isError()) {
    return createError(PerfOutputError::SystemError, exp_fd.takeError())
           << "Fail to create perf_event output point";
  }
  instance.fd_ = exp_fd.take();

  instance.data_ptr_ = mmap(NULL,
                            instance.size_,
                            PROT_READ | PROT_WRITE,
                            MAP_SHARED,
                            instance.fd_,
                            0);
  if (instance.data_ptr_ == MAP_FAILED) {
    instance.data_ptr_ = nullptr;
    return createError(PerfOutputError::SystemError)
           << "Fail to mmap memory for perf event of PerfOutput "
           << boost::io::quoted(strerror(errno));
  }
  if (ioctl(instance.fd_, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    return createError(PerfOutputError::SystemError)
           << "Fail to enable perf event of PerfOutput "
           << boost::io::quoted(strerror(errno));
  }
  return Expected<PerfOutput<MessageType>, PerfOutputError>(
      std::move(instance));
}

template <typename MessageType>
ExpectedSuccess<PerfOutputError> PerfOutput<MessageType>::unload() {
  if (fd_ < 0) {
    return Success{};
  }
  bool failed = false;
  std::string err_msg;
  int ret = ioctl(fd_, PERF_EVENT_IOC_DISABLE, 0);
  if (ret < 0) {
    failed = true;
    err_msg += " perf event disabling failed: \"";
    err_msg += strerror(errno);
    err_msg += "\". ";
  }
  if (data_ptr_ != nullptr) {
    ret = munmap(data_ptr_, size_);
    if (ret < 0) {
      failed = true;
      err_msg += " Memory unmap failed: \"";
      err_msg += strerror(errno);
      err_msg += "\".";
    }
    data_ptr_ = nullptr;
  }
  ret = close(fd_);
  if (ret < 0) {
    failed = true;
    err_msg += " File descriptor was closed with error: \"";
    err_msg += strerror(errno);
    err_msg += "\".";
  }
  fd_ = -1;
  if (failed) {
    return createError(PerfOutputError::SystemError) << err_msg;
  }
  return Success{};
}

template <typename MessageType>
void PerfOutput<MessageType>::forceUnload() {
  auto const exp = unload();
  if (exp.isError()) {
    LOG(ERROR) << "Could not unload perf event output point "
               << boost::io::quoted(exp.getError().getMessage());
  }
}

template <typename MessageType>
int PerfOutput<MessageType>::fd() const {
  return fd_;
}

template <typename MessageType>
void const* PerfOutput<MessageType>::data() const {
  return data_ptr_;
}

template <typename MessageType>
std::size_t PerfOutput<MessageType>::size() const {
  return size_;
}

namespace impl {

using ByteType = std::uint8_t;
/**
 * Circular buffer reading is in separate function only for the tests
 *
 * |<--------------- mapped memory ------------------------------------------->|
 * [header]   |<---------------------- data_size ----------------------------->|
 * [xxxx.....................xxxxxxxxxxxxxxxxxxxxxxxxxxx.......................]
 *            |              |            ^             |
 *         data_ptr      data_tail        |         data_head
 *                                 wrapped messages
 */
template <typename WrappedMessage,
          typename MessageType = decltype(std::declval<WrappedMessage>().msg)>
inline ExpectedSuccess<PerfOutputError>
consumeWrappedMessagesFromCircularBuffer(ByteType const* data_ptr,
                                         __u64 data_tail,
                                         __u64 const data_head,
                                         __u64 const buffer_size,
                                         std::vector<MessageType>& messages) {
  __u64 offset = data_tail % buffer_size;
  while (data_tail < data_head) {
    if (offset + sizeof(WrappedMessage) > buffer_size) {
      // wrapped_message is probably splited, let's do continuous copy
      auto wrapped_message = WrappedMessage{};
      __u64 record_offset = buffer_size - offset;
      std::copy(data_ptr + offset,
                data_ptr + buffer_size,
                reinterpret_cast<ByteType*>(&wrapped_message));
      offset = 0u;
      auto const header_size = sizeof(wrapped_message.header);
      if (record_offset < header_size) {
        __u64 const header_remain_len = header_size - record_offset;
        std::copy(
            data_ptr,
            data_ptr + header_remain_len,
            reinterpret_cast<ByteType*>(&wrapped_message) + record_offset);
        record_offset += header_remain_len;
        offset += header_remain_len;
      }
      if (wrapped_message.header.size > record_offset) {
        __u64 remain_len = wrapped_message.header.size - record_offset;
        std::copy(
            data_ptr + offset,
            data_ptr + offset + remain_len,
            reinterpret_cast<ByteType*>(&wrapped_message) + record_offset);
      }
      messages.push_back(wrapped_message.msg);
      data_tail += wrapped_message.header.size;
      offset = data_tail % buffer_size;
    } else {
      WrappedMessage wrapped_message;
      memcpy(&wrapped_message, (data_ptr + offset), sizeof(WrappedMessage));
      messages.emplace_back(wrapped_message.msg);
      offset += wrapped_message.header.size;
      data_tail += wrapped_message.header.size;
    }
  }
  return Success{};
}

} // namespace impl

template <typename MessageType>
ExpectedSuccess<PerfOutputError> PerfOutput<MessageType>::read(
    MessageBatchType& dst) {
  static_assert(std::is_trivial<MessageType>::value,
                "message type must be trivial, because it comes from ASM code "
                "at the end");
  if (fd_ < 0) {
    return createError(PerfOutputError::LogicError)
           << "Attept to read from not loaded perf output";
  }
  auto header = static_cast<struct perf_event_mmap_page*>(data_ptr_);
  if (header->data_head == header->data_tail) {
    return Success{};
  }
  auto status = impl::consumeWrappedMessagesFromCircularBuffer<WrappedMessage>(
      (impl::ByteType const*)data() + header->data_offset,
      header->data_tail,
      header->data_head,
      header->data_size,
      dst);
  header->data_tail = header->data_head;
  return status;
}

template <typename MessageType>
PerfOutputsPoll<MessageType>::PerfOutputsPoll(PerfOutputsPoll&& other)
    : outputs_(std::move(other.outputs_)), fds_(std::move(other.fds_)) {
  other.outputs_.clear();
  other.fds_.clear();
}

template <typename MessageType>
PerfOutputsPoll<MessageType>& PerfOutputsPoll<MessageType>::operator=(
    PerfOutputsPoll&& other) {
  std::swap(outputs_, other.outputs_);
  std::swap(fds_, other.fds_);
  return *this;
}

template <typename MessageType>
std::size_t PerfOutputsPoll<MessageType>::size() const {
  return outputs_.size();
}

template <typename MessageType>
ExpectedSuccess<PerfOutputError> PerfOutputsPoll<MessageType>::add(
    PerfOutput<MessageType> output) {
  if (outputs_.size() == cpu::kMaskSize) {
    return createError(PerfOutputError::LogicError)
           << "osquery support no more than " << cpu::kMaskSize
           << " cpu, change cpu::kMaskSize and recompile";
  }
  struct pollfd pfd;
  pfd.fd = output.fd();
  pfd.events = POLLIN;
  fds_.push_back(pfd);
  outputs_.push_back(std::move(output));
  return Success{};
}

template <typename MessageType>
ExpectedSuccess<PerfOutputError> PerfOutputsPoll<MessageType>::read(
    PerfOutputsPoll<MessageType>::MessageBatchType& batch) {
  while (true) {
    int ret = ::poll(fds_.data(), fds_.size(), poll_timeout_.count());
    if (ret < 0) {
      return createError(PerfOutputError::SystemError)
             << "perf output polling failed" << strerror(errno);
    } else if (ret == 0) {
      // timeout; no event detected
    } else {
      batch.clear();
      for (std::size_t index = 0; index < fds_.size(); ++index) {
        if ((fds_[index].revents & POLLIN) != 0) {
          fds_[index].revents = 0;
          auto status = outputs_[index].read(batch);
          if (status.isError()) {
            return createError(PerfOutputError::LogicError, status.takeError())
                   << "read in perf output poll failed";
          }
        }
      }
      return Success{};
    }
  }
}

} // namespace ebpf
} // namespace osquery
