/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/experimental/tracing/linux/syscall_event.h>

namespace osquery {
namespace {

class SyscallsTracepointTests : public testing::Test {};
class EnterExitJoinerTests : public testing::Test {};

template <events::syscall::EventType enter, events::syscall::EventType exit>
void checkEventPair() {
  static_assert(enter == events::syscall::flipEventType(exit),
                "flipEventType have to flip Exit to Enter");
  static_assert(exit == events::syscall::flipEventType(enter),
                "flipEventType have to flip Enter to Exit");
  static_assert(enter == events::syscall::flipEventType(
                             events::syscall::flipEventType(enter)),
                "flipEventType applied twice to Enter have to return exactly "
                "the same Enter");
  static_assert(exit == events::syscall::flipEventType(
                            events::syscall::flipEventType(exit)),
                "flipEventType applied twice to Exit have to return exactly "
                "the same Exit");
}

TEST_F(SyscallsTracepointTests, SyscallEvent_flipType) {
  checkEventPair<events::syscall::EventType::KillEnter,
                 events::syscall::EventType::KillExit>();
  checkEventPair<events::syscall::EventType::SetuidEnter,
                 events::syscall::EventType::SetuidExit>();
  static_assert(
      events::syscall::EventType::Unknown ==
          events::syscall::flipEventType(events::syscall::EventType::Unknown),
      "syscall::EventType::Unknown could not be fliped");
}

TEST_F(SyscallsTracepointTests, SyscallEvent_isTypeExit) {
  static_assert(
      events::syscall::isEventTypeExit(events::syscall::EventType::KillExit),
      "");
  static_assert(
      events::syscall::isEventTypeExit(events::syscall::EventType::SetuidExit),
      "");
  static_assert(
      !events::syscall::isEventTypeExit(events::syscall::EventType::Unknown),
      "");
  static_assert(!events::syscall::isEventTypeExit(
                    events::syscall::EventType::SetuidEnter),
                "");
  static_assert(!events::syscall::isEventTypeExit(
                    events::syscall::EventType::SetuidEnter),
                "");
}

TEST_F(SyscallsTracepointTests, SyscallEvent_isTypeEnter) {
  static_assert(
      !events::syscall::isEventTypeEnter(events::syscall::EventType::KillExit),
      "");
  static_assert(!events::syscall::isEventTypeEnter(
                    events::syscall::EventType::SetuidExit),
                "");
  static_assert(
      !events::syscall::isEventTypeEnter(events::syscall::EventType::Unknown),
      "");
  static_assert(events::syscall::isEventTypeEnter(
                    events::syscall::EventType::SetuidEnter),
                "");
  static_assert(events::syscall::isEventTypeEnter(
                    events::syscall::EventType::SetuidEnter),
                "");
}

TEST_F(EnterExitJoinerTests,
       EnterExitJoiner_many_pair_enter_exit_events_with_different_pid) {
  auto joiner = events::syscall::EnterExitJoiner{};
  {
    auto enter_event = events::syscall::Event{};
    enter_event.type = events::syscall::EventType::SetuidEnter;
    enter_event.tgid = 146;
    enter_event.body.setuid_enter.arg_uid = 48;
    enter_event.body.setuid_enter.uid = 49;
    enter_event.body.setuid_enter.gid = 50;
    enter_event.return_value = -1;
    for (int pid = 0; pid < 64; ++pid) {
      enter_event.pid = pid;
      auto out = joiner.join(enter_event);
      ASSERT_FALSE(out);
    }
  }
  auto exit_event = events::syscall::Event{};
  exit_event.type = events::syscall::EventType::SetuidExit;
  exit_event.tgid = 146;
  exit_event.body.exit.ret = -59;

  for (int pid = 0; pid < 64; ++pid) {
    exit_event.pid = pid;

    auto event = joiner.join(exit_event);
    ASSERT_TRUE(event);
    EXPECT_EQ(event->type, events::syscall::EventType::SetuidEnter);
    EXPECT_EQ(event->pid, pid);
    EXPECT_EQ(event->tgid, 146);
    EXPECT_EQ(event->body.setuid_enter.arg_uid, 48);
    EXPECT_EQ(event->body.setuid_enter.uid, 49);
    EXPECT_EQ(event->body.setuid_enter.gid, 50);
    EXPECT_EQ(event->return_value, -59);
  }

  EXPECT_TRUE(joiner.isEmpty());
}

TEST_F(EnterExitJoinerTests, EnterExitJoiner_one_non_paired_event_by_pid) {
  auto joiner = events::syscall::EnterExitJoiner{};

  auto enter_event = events::syscall::Event{};
  enter_event.type = events::syscall::EventType::SetuidEnter;
  enter_event.pid = 45;
  enter_event.tgid = 146;
  enter_event.body.setuid_enter.arg_uid = 48;
  enter_event.body.setuid_enter.uid = 49;
  enter_event.body.setuid_enter.gid = 50;
  enter_event.return_value = -1;

  auto out = joiner.join(enter_event);
  ASSERT_FALSE(out);

  auto exit_event = events::syscall::Event{};
  exit_event.type = events::syscall::EventType::SetuidExit;
  exit_event.pid = enter_event.pid + 12; // pid is different
  exit_event.tgid = enter_event.tgid;
  exit_event.body.exit.ret = -59;

  auto event = joiner.join(exit_event);
  ASSERT_FALSE(event);
  ASSERT_FALSE(joiner.isEmpty());
}

TEST_F(EnterExitJoinerTests, EnterExitJoiner_one_non_paired_event_by_type) {
  auto joiner = events::syscall::EnterExitJoiner{};

  auto enter_event = events::syscall::Event{};
  enter_event.type = events::syscall::EventType::SetuidEnter;
  enter_event.pid = 45;
  enter_event.tgid = 146;
  enter_event.body.setuid_enter.arg_uid = 48;
  enter_event.body.setuid_enter.uid = 49;
  enter_event.body.setuid_enter.gid = 50;
  enter_event.return_value = -1;

  auto out = joiner.join(enter_event);
  ASSERT_FALSE(out);

  auto exit_event = events::syscall::Event{};
  exit_event.type = events::syscall::EventType::KillExit; // type is different
  exit_event.pid = enter_event.pid;
  exit_event.tgid = enter_event.tgid;
  exit_event.body.exit.ret = -59;

  auto event = joiner.join(exit_event);
  ASSERT_FALSE(event);
  EXPECT_FALSE(joiner.isEmpty());
}

TEST_F(EnterExitJoinerTests, EnterExitJoiner_many_same_enter_exit_events) {
  auto joiner = events::syscall::EnterExitJoiner{};

  auto enter_event = events::syscall::Event{};
  enter_event.type = events::syscall::EventType::SetuidEnter;
  enter_event.pid = 218;
  enter_event.tgid = 146;
  enter_event.body.setuid_enter.arg_uid = 165;
  enter_event.body.setuid_enter.uid = 49;
  enter_event.body.setuid_enter.gid = 50;
  enter_event.return_value = -1;
  for (int i = 0; i < 12; ++i) {
    joiner.join(enter_event);
  }

  auto exit_event = events::syscall::Event{};
  exit_event.type = events::syscall::EventType::SetuidExit;
  exit_event.pid = enter_event.pid;
  exit_event.tgid = enter_event.tgid;
  exit_event.body.exit.ret = -59;

  for (int i = 0; i < 12; ++i) {
    auto event = joiner.join(exit_event);
    ASSERT_TRUE(event);

    EXPECT_EQ(event->type, events::syscall::EventType::SetuidEnter);
    EXPECT_EQ(event->pid, enter_event.pid);
    EXPECT_EQ(event->tgid, enter_event.tgid);
    EXPECT_EQ(event->body.setuid_enter.arg_uid,
              enter_event.body.setuid_enter.arg_uid);
    EXPECT_EQ(event->body.setuid_enter.uid, enter_event.body.setuid_enter.uid);
    EXPECT_EQ(event->body.setuid_enter.gid, enter_event.body.setuid_enter.gid);
    EXPECT_EQ(event->return_value, exit_event.body.exit.ret);
  }

  EXPECT_TRUE(joiner.isEmpty());
}

} // namespace
} // namespace osquery
