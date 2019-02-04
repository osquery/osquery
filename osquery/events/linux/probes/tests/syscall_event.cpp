/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/events/linux/probes/syscall_event.h>

namespace osquery {
namespace {

class SyscallsTracepointTests : public testing::Test {};
class EnterExitJoinerTests : public testing::Test {};

template <events::syscall::Type enter, events::syscall::Type exit>
void checkEventPair() {
  static_assert(enter == events::syscall::flipType(exit),
                "flipType have to flip Exit to Enter");
  static_assert(exit == events::syscall::flipType(enter),
                "flipType have to flip Enter to Exit");
  static_assert(
      enter == events::syscall::flipType(events::syscall::flipType(enter)),
      "flipType applied twice to Enter have to return exactly the same Enter");
  static_assert(
      exit == events::syscall::flipType(events::syscall::flipType(exit)),
      "flipType applied twice to Exit have to return exactly the same Exit");
}

TEST_F(SyscallsTracepointTests, SyscallEvent_flipType) {
  checkEventPair<events::syscall::Type::KillEnter,
                 events::syscall::Type::KillExit>();
  checkEventPair<events::syscall::Type::SetuidEnter,
                 events::syscall::Type::SetuidExit>();
  static_assert(events::syscall::Type::Unknown ==
                    events::syscall::flipType(events::syscall::Type::Unknown),
                "syscall::Type::Unknown could not be fliped");
}

TEST_F(SyscallsTracepointTests, SyscallEvent_isTypeExit) {
  static_assert(events::syscall::isTypeExit(events::syscall::Type::KillExit),
                "");
  static_assert(events::syscall::isTypeExit(events::syscall::Type::SetuidExit),
                "");
  static_assert(!events::syscall::isTypeExit(events::syscall::Type::Unknown),
                "");
  static_assert(
      !events::syscall::isTypeExit(events::syscall::Type::SetuidEnter), "");
  static_assert(
      !events::syscall::isTypeExit(events::syscall::Type::SetuidEnter), "");
}

TEST_F(SyscallsTracepointTests, SyscallEvent_isTypeEnter) {
  static_assert(!events::syscall::isTypeEnter(events::syscall::Type::KillExit),
                "");
  static_assert(
      !events::syscall::isTypeEnter(events::syscall::Type::SetuidExit), "");
  static_assert(!events::syscall::isTypeEnter(events::syscall::Type::Unknown),
                "");
  static_assert(
      events::syscall::isTypeEnter(events::syscall::Type::SetuidEnter), "");
  static_assert(
      events::syscall::isTypeEnter(events::syscall::Type::SetuidEnter), "");
}

TEST_F(EnterExitJoinerTests,
       EnterExitJoiner_many_pair_enter_exit_events_with_different_pid) {
  auto joiner = events::syscall::EnterExitJoiner{};
  {
    auto enter_event = events::syscall::Event{};
    enter_event.type = events::syscall::Type::SetuidEnter;
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
  exit_event.type = events::syscall::Type::SetuidExit;
  exit_event.tgid = 146;
  exit_event.body.exit.ret = -59;

  for (int pid = 0; pid < 64; ++pid) {
    exit_event.pid = pid;

    auto event = joiner.join(exit_event);
    ASSERT_TRUE(event);
    EXPECT_EQ(event->type, events::syscall::Type::SetuidEnter);
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
  enter_event.type = events::syscall::Type::SetuidEnter;
  enter_event.pid = 45;
  enter_event.tgid = 146;
  enter_event.body.setuid_enter.arg_uid = 48;
  enter_event.body.setuid_enter.uid = 49;
  enter_event.body.setuid_enter.gid = 50;
  enter_event.return_value = -1;

  auto out = joiner.join(enter_event);
  ASSERT_FALSE(out);

  auto exit_event = events::syscall::Event{};
  exit_event.type = events::syscall::Type::SetuidExit;
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
  enter_event.type = events::syscall::Type::SetuidEnter;
  enter_event.pid = 45;
  enter_event.tgid = 146;
  enter_event.body.setuid_enter.arg_uid = 48;
  enter_event.body.setuid_enter.uid = 49;
  enter_event.body.setuid_enter.gid = 50;
  enter_event.return_value = -1;

  auto out = joiner.join(enter_event);
  ASSERT_FALSE(out);

  auto exit_event = events::syscall::Event{};
  exit_event.type = events::syscall::Type::KillExit; // type is different
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
  enter_event.type = events::syscall::Type::SetuidEnter;
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
  exit_event.type = events::syscall::Type::SetuidExit;
  exit_event.pid = enter_event.pid;
  exit_event.tgid = enter_event.tgid;
  exit_event.body.exit.ret = -59;

  for (int i = 0; i < 12; ++i) {
    auto event = joiner.join(exit_event);
    ASSERT_TRUE(event);

    EXPECT_EQ(event->type, events::syscall::Type::SetuidEnter);
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
