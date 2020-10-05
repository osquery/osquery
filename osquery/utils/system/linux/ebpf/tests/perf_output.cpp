/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/linux/ebpf/perf_output.h>

#include <gtest/gtest.h>

#include <array>

namespace osquery {
namespace ebpf {

class PerfOutputTests : public testing::Test {};

struct TestMessage {
  int a_;
  int b_;
  char c_;
  char d_;
};

TEST_F(PerfOutputTests, load) {
  auto output_exp = ebpf::PerfOutput<TestMessage>::load(0u, 512u);
  // permission denied, test runs under non root user
  ASSERT_TRUE(output_exp.isError());
}

TEST_F(PerfOutputTests, move_constructor) {
  auto buf = std::array<char, 4>{};
  auto from_obj = ebpf::PerfOutput<TestMessage>{};
  from_obj.size_ = buf.size();
  from_obj.fd_ = 42;
  from_obj.data_ptr_ = static_cast<void*>(buf.data());

  auto to_obj = std::move(from_obj);

  EXPECT_EQ(to_obj.size_, buf.size());
  EXPECT_EQ(to_obj.fd_, 42);
  EXPECT_EQ(to_obj.data_ptr_, static_cast<void*>(buf.data()));

  EXPECT_LE(from_obj.fd_, 0);
  EXPECT_EQ(from_obj.data_ptr_, nullptr);

  // to prevent closing non existing file descriptor
  to_obj.fd_ = -1;
}

TEST_F(PerfOutputTests, assigning_constructor) {
  auto buf = std::array<char, 8>{};
  auto from_obj = ebpf::PerfOutput<TestMessage>{};
  from_obj.size_ = buf.size();
  from_obj.fd_ = 42;
  from_obj.data_ptr_ = static_cast<void*>(buf.data());

  auto to_obj = ebpf::PerfOutput<TestMessage>{};
  to_obj = std::move(from_obj);

  EXPECT_EQ(to_obj.size_, buf.size());
  EXPECT_EQ(to_obj.fd_, 42);
  EXPECT_EQ(to_obj.data_ptr_, static_cast<void*>(buf.data()));

  EXPECT_LE(from_obj.fd_, 0);
  EXPECT_EQ(from_obj.data_ptr_, nullptr);

  // to prevent closing non existing file descriptor
  to_obj.fd_ = -1;
}

TEST_F(PerfOutputTests,
       impl_consumeWrappedMessagesFromCircularBuffer_without_wrapping) {
  using WrappedMessage = ebpf::PerfOutput<TestMessage>::WrappedMessage;
  auto const test_size = std::size_t{9};
  auto buf = std::vector<ebpf::impl::ByteType>(
      sizeof(WrappedMessage) * test_size + 128, 0);
  auto buf_ptr = &buf[0];
  for (std::size_t i = 0; i < test_size; ++i) {
    auto wrapped = WrappedMessage{};
    wrapped.msg.a_ = i + 1;
    wrapped.msg.b_ = i * 2 + 2;
    wrapped.msg.c_ = 'j';
    wrapped.msg.d_ = 'k';
    wrapped.size = sizeof(TestMessage);
    wrapped.header.type = PERF_RECORD_SAMPLE;
    wrapped.header.size = sizeof(WrappedMessage);
    auto const wrapped_ptr =
        reinterpret_cast<ebpf::impl::ByteType const*>(&wrapped);
    std::copy(wrapped_ptr, wrapped_ptr + sizeof(WrappedMessage), buf_ptr);
    buf_ptr += sizeof(WrappedMessage);
  }
  auto dst = std::vector<TestMessage>{};
  auto status =
      ebpf::impl::consumeWrappedMessagesFromCircularBuffer<WrappedMessage>(
          &buf[0],
          0,
          static_cast<std::size_t>(buf_ptr - &buf[0]),
          buf.size(),
          dst);
  ASSERT_FALSE(status.isError());
  ASSERT_EQ(dst.size(), test_size);
  for (std::size_t i = 0; i < test_size; ++i) {
    EXPECT_EQ(dst[i].a_, static_cast<int>(i + 1));
    EXPECT_EQ(dst[i].b_, static_cast<int>(i * 2 + 2));
    EXPECT_EQ(dst[i].c_, 'j');
    EXPECT_EQ(dst[i].d_, 'k');
  }
}

TEST_F(PerfOutputTests,
       impl_consumeWrappedMessagesFromCircularBuffer_simply_wrapped) {
  using WrappedMessage = ebpf::PerfOutput<TestMessage>::WrappedMessage;
  auto const test_size = std::size_t{9};
  auto buf =
      std::vector<ebpf::impl::ByteType>(sizeof(WrappedMessage) * test_size, 0);
  auto buf_ptr = &buf[0];
  for (std::size_t i = 0; i < test_size; ++i) {
    auto wrapped = WrappedMessage{};
    wrapped.msg.a_ = i + 1;
    wrapped.msg.b_ = i * 2 + 2;
    wrapped.msg.c_ = 'y';
    wrapped.msg.d_ = 'x';
    wrapped.size = sizeof(TestMessage);
    wrapped.header.type = PERF_RECORD_SAMPLE;
    wrapped.header.size = sizeof(WrappedMessage);
    auto const wrapped_ptr =
        reinterpret_cast<ebpf::impl::ByteType const*>(&wrapped);
    std::copy(wrapped_ptr, wrapped_ptr + sizeof(WrappedMessage), buf_ptr);
    buf_ptr += sizeof(WrappedMessage);
  }
  auto dst = std::vector<TestMessage>{};
  auto status =
      ebpf::impl::consumeWrappedMessagesFromCircularBuffer<WrappedMessage>(
          &buf[0],
          sizeof(WrappedMessage),
          buf.size() + sizeof(WrappedMessage),
          buf.size(),
          dst);
  ASSERT_FALSE(status.isError()) << status.getError().getMessage();
  ASSERT_EQ(dst.size(), test_size);
  for (std::size_t i = 0; i < test_size; ++i) {
    EXPECT_EQ(dst[i].c_, 'y') << i;
    EXPECT_EQ(dst[i].d_, 'x');
  }
  EXPECT_EQ(dst.back().a_, 1);
  EXPECT_EQ(dst.back().b_, 2);
  EXPECT_EQ(dst[0].a_, 2);
  EXPECT_EQ(dst[0].b_, 4);
}

TEST_F(PerfOutputTests,
       impl_consumeWrappedMessagesFromCircularBuffer_splited_record_wrapping) {
  using WrappedMessage = ebpf::PerfOutput<TestMessage>::WrappedMessage;
  auto const test_size = std::size_t{3};
  auto buf = std::vector<ebpf::impl::ByteType>(
      sizeof(WrappedMessage) * test_size + 154, 0);
  auto const first_part_size = 8;
  auto const tail = buf.size() - sizeof(WrappedMessage) - first_part_size;
  auto const head = tail + sizeof(WrappedMessage) * test_size;

  auto wrapped = WrappedMessage{};
  wrapped.msg.a_ = 1;
  wrapped.msg.b_ = 2;
  wrapped.msg.c_ = 't';
  wrapped.msg.d_ = 'i';
  wrapped.size = sizeof(TestMessage);
  wrapped.header.type = PERF_RECORD_SAMPLE;
  wrapped.header.size = sizeof(WrappedMessage);
  auto const wrapped_ptr =
      reinterpret_cast<ebpf::impl::ByteType const*>(&wrapped);
  std::copy(wrapped_ptr, wrapped_ptr + sizeof(WrappedMessage), &buf[0] + tail);

  wrapped.msg.a_ = 3;
  wrapped.msg.b_ = 4;
  std::copy(wrapped_ptr,
            wrapped_ptr + first_part_size,
            &buf[0] + tail + sizeof(WrappedMessage));
  std::copy(wrapped_ptr + first_part_size,
            wrapped_ptr + sizeof(WrappedMessage),
            &buf[0]);

  wrapped.msg.a_ = 5;
  wrapped.msg.b_ = 6;
  std::copy(wrapped_ptr,
            wrapped_ptr + sizeof(WrappedMessage),
            &buf[0] + sizeof(WrappedMessage) - first_part_size);

  auto dst = std::vector<TestMessage>{};
  auto status =
      ebpf::impl::consumeWrappedMessagesFromCircularBuffer<WrappedMessage>(
          &buf[0], tail, head, buf.size(), dst);
  ASSERT_FALSE(status.isError()) << status.getError().getMessage();
  ASSERT_EQ(dst.size(), test_size);
  for (std::size_t i = 0; i < test_size; ++i) {
    EXPECT_EQ(dst[i].c_, 't');
    EXPECT_EQ(dst[i].d_, 'i');
  }
  EXPECT_EQ(dst[0].a_, 1);
  EXPECT_EQ(dst[0].b_, 2);
  EXPECT_EQ(dst[1].a_, 3);
  EXPECT_EQ(dst[1].b_, 4);
  EXPECT_EQ(dst[2].a_, 5);
  EXPECT_EQ(dst[2].b_, 6);
}

} // namespace ebpf
} // namespace osquery
