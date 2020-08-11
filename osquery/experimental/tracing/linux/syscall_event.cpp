/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/experimental/tracing/linux/syscall_event.h>

namespace osquery {
namespace events {
namespace syscall {

namespace {

static constexpr EnterExitJoiner::CounterType kCounterLimit = 256;

EnterExitJoiner::KeyType createKey(EventType const type,
                                   __s32 const pid,
                                   __s32 const tgid) {
  auto key = EnterExitJoiner::KeyType(static_cast<std::uint32_t>(pid));
  key <<= 32;
  key |= static_cast<std::uint32_t>(tgid);
  key <<= 32;
  key |= static_cast<std::uint32_t>(type);
  return key;
}

} // namespace

boost::optional<Event> EnterExitJoiner::join(Event in_event) {
  ++counter_;
  if (counter_ > kCounterLimit) {
    drop_stuck_events();
    counter_ = 0;
  }
  auto const inv_key =
      createKey(flipEventType(in_event.type), in_event.pid, in_event.tgid);

  auto it = table_.find(inv_key);
  if (it == table_.end()) {
    auto const key = createKey(in_event.type, in_event.pid, in_event.tgid);
    // As far as `return_value` is not used while the event is in the table_
    // we can use it to preserve the counter value as the age of the event.
    in_event.return_value = counter_;
    table_.emplace(key, std::move(in_event));
    return boost::none;
  }

  if (isEventTypeExit(in_event.type)) {
    auto enter = std::move(it->second);
    enter.return_value = in_event.body.exit.ret;
    table_.erase(it);
    return enter;
  }
  in_event.return_value = it->second.body.exit.ret;
  table_.erase(it);
  return in_event;
}

bool EnterExitJoiner::isEmpty() const {
  return table_.empty();
}

void EnterExitJoiner::drop_stuck_events() {
  // As far as `table_` is relatively small we can afford to iterarte over it
  // once in a kCounterLimit events in order to clean it up.
  for (auto it = table_.begin(); it != table_.end();) {
    if (it->second.return_value < 0) {
      it = table_.erase(it);
    } else {
      it->second.return_value -= kCounterLimit;
      ++it;
    }
  }
}

} // namespace syscall
} // namespace events
} // namespace osquery
