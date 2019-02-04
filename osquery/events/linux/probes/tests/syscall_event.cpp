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

} // namespace
} // namespace osquery
