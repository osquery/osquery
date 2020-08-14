/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/system/linux/perf_event/perf_event.h>

#include <osquery/logger/logger.h>

#include <gtest/gtest_prod.h>

#include <chrono>
#include <type_traits>
#include <vector>

#include <poll.h>

namespace osquery {
namespace ebpf {

enum class PerfOutputError {
  Unknown = 1,
  SystemError = 2,
  LogicError = 3,
};

template <typename MessageType>
class PerfOutput final {
 public:
  PerfOutput(PerfOutput&&);
  PerfOutput& operator=(PerfOutput&&);

  PerfOutput(PerfOutput const&) = delete;
  PerfOutput& operator=(PerfOutput const&) = delete;

  ~PerfOutput();

  static Expected<PerfOutput<MessageType>, PerfOutputError> load(
      std::size_t cpu, std::size_t size);

  int fd() const;

  void const* data() const;

  std::size_t size() const;

  using MessageBatchType = std::vector<MessageType>;

#pragma pack(push, 1)
  struct WrappedMessage {
    struct perf_event_header header;
    std::uint32_t size;
    MessageType msg;
  };
#pragma pack(pop)

  ExpectedSuccess<PerfOutputError> read(MessageBatchType& dst);

 private:
  explicit PerfOutput() = default;
  ExpectedSuccess<PerfOutputError> unload();

  void forceUnload();

  static_assert(
      sizeof(WrappedMessage) <
          std::numeric_limits<
              decltype(std::declval<struct perf_event_header>().size)>::max(),
      "A MessageType is too big, linux perf event can not support it");

  FRIEND_TEST(PerfOutputTests, move_constructor);
  FRIEND_TEST(PerfOutputTests, assigning_constructor);

 private:
  std::size_t size_;
  int fd_ = -1;
  void* data_ptr_ = nullptr;
};

template <typename MessageType>
class PerfOutputsPoll final {
 public:
  explicit PerfOutputsPoll() = default;

  PerfOutputsPoll(PerfOutputsPoll&&);
  PerfOutputsPoll& operator=(PerfOutputsPoll&&);

  PerfOutputsPoll(PerfOutputsPoll const&) = delete;
  PerfOutputsPoll& operator=(PerfOutputsPoll const&) = delete;

  std::size_t size() const;

  /**
   * Add new perf output to the poll
   */
  ExpectedSuccess<PerfOutputError> add(PerfOutput<MessageType> output);

  using MessageBatchType = typename PerfOutput<MessageType>::MessageBatchType;

  /**
   * Blocking method of reading new messages from the polling outputs
   */
  ExpectedSuccess<PerfOutputError> read(MessageBatchType& batch);

 private:
  std::vector<PerfOutput<MessageType>> outputs_;
  std::vector<struct pollfd> fds_;
  const std::chrono::milliseconds poll_timeout_ = std::chrono::seconds{2};
};

} // namespace ebpf
} // namespace osquery

#include <osquery/utils/system/linux/ebpf/perf_output_impl.h>
