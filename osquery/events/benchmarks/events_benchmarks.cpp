/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <benchmark/benchmark.h>

#include <osquery/events.h>
#include <osquery/tables.h>

namespace osquery {

class BenchmarkEventPublisher
    : public EventPublisher<SubscriptionContext, EventContext> {
  DECLARE_PUBLISHER("benchmark");

 public:
  void benchmarkFire() {
    auto ec = createEventContext();
    fire(ec, 0);
  }
};

static void EVENTS_register(benchmark::State& state) {
  while (state.KeepRunning()) {
    auto pub = std::make_shared<BenchmarkEventPublisher>();
    auto type = pub->type();

    EventFactory::registerEventPublisher(pub);
    auto pub2 = EventFactory::getEventPublisher("benchmark");
  }
}

BENCHMARK(EVENTS_register);

class BenchmarkEventSubscriber
    : public EventSubscriber<BenchmarkEventPublisher> {
 public:
  BenchmarkEventSubscriber() { setName("benchmark"); }

  Status Callback(const EventContextRef& ec, const void* user_data) {
    return Status(0, "OK");
  }

  void benchmarkInit() {
    auto sub_ctx = createSubscriptionContext();
    subscribe(&BenchmarkEventSubscriber::Callback, sub_ctx, nullptr);
  }

  void benchmarkAdd(int t) {
    Row r;
    r["testing"] = "hello";
    add(r, t);
  }

  void clearRows() {
    expire_events_ = true;
    expire_time_ = -1;
    getIndexes(0, 0);
  }

  void benchmarkGet(int low, int high) { auto results = get(low, high); }
};

static void EVENTS_subscribe_fire(benchmark::State& state) {
  // Register a publisher.
  auto pub = std::make_shared<BenchmarkEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  // Register a subscriber.
  auto sub = std::make_shared<BenchmarkEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  // Simulate the event factory initialization.
  // This creates a subscription and adds it and a callback.
  sub->benchmarkInit();

  while (state.KeepRunning()) {
    // Fire an event from the publisher, and let the subscriber handle.
    pub->benchmarkFire();
  }
}

BENCHMARK(EVENTS_subscribe_fire);

static void EVENTS_add_events(benchmark::State& state) {
  auto pub = std::make_shared<BenchmarkEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  auto sub = std::make_shared<BenchmarkEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  // Simulate the event factory initialization.
  sub->benchmarkInit();

  int i = 0;
  while (state.KeepRunning()) {
    sub->benchmarkAdd(i++);
  }
  sub->clearRows();
}

BENCHMARK(EVENTS_add_events);

static void EVENTS_retrieve_events(benchmark::State& state) {
  auto sub = std::make_shared<BenchmarkEventSubscriber>();

  for (int i = 0; i < 10000; i++) {
    sub->benchmarkAdd(i++);
  }

  while (state.KeepRunning()) {
    sub->benchmarkGet(state.range_x(), state.range_y());
  }

  sub->clearRows();
}

BENCHMARK(EVENTS_retrieve_events)
    ->ArgPair(0, 100)
    ->ArgPair(0, 500)
    ->ArgPair(0, 1000)
    ->ArgPair(0, 10000);
}
