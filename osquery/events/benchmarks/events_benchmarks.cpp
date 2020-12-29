/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <benchmark/benchmark.h>

#include <osquery/config/config.h>
#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>

#include "osquery/tests/test_util.h"

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
  RegistryFactory::get().setActive("database", "rocksdb");

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
  BenchmarkEventSubscriber() {
    setName("benchmark");
  }

  Status Callback(const ECRef& ec, const SCRef& sc) {
    return Status::success();
  }

  void benchmarkInit() {
    auto sub_ctx = createSubscriptionContext();
    subscribe(&BenchmarkEventSubscriber::Callback, sub_ctx);
  }

  void benchmarkAdd(int t) {
    Row r;
    r["testing"] = "hello";

    std::vector<Row> row_list = {std::move(r)};
    addBatch(row_list, t);
  }

  void clearRows() {
    auto ee = expire_events_;
    auto et = expire_time_;
    expire_events_ = true;
    expire_time_ = -1;
    getIndexes(0, 0);
    expire_events_ = ee;
    expire_time_ = et;
  }

  void benchmarkGet(int low, int high) {
    RowGenerator::pull_type generator(std::bind(
        &EventSubscriberPlugin::get, this, std::placeholders::_1, low, high));
    if (!generator) {
      return;
    }

    while (generator) {
      generator.get();
      generator();
    }
  }
};

static void EVENTS_subscribe_fire(benchmark::State& state) {
  // Setup the event config parser plugin.
  auto plugin = Config::get().getParser("events");
  plugin->setUp();

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

  for (int i = 0; i < state.range(1); i++) {
    sub->benchmarkAdd(i++);
  }

  while (state.KeepRunning()) {
    sub->benchmarkGet(state.range(0), state.range(1));
  }

  sub->clearRows();
}

BENCHMARK(EVENTS_retrieve_events)
    ->ArgPair(0, 100)
    ->ArgPair(0, 1000)
    ->ArgPair(0, 10000);

static void EVENTS_gentable(benchmark::State& state) {
  auto sub = std::make_shared<BenchmarkEventSubscriber>();

  for (int i = 0; i < state.range(1); i++) {
    sub->benchmarkAdd(i++);
  }

  while (state.KeepRunning()) {
    genRows(sub.get());
  }

  sub->clearRows();
}

BENCHMARK(EVENTS_gentable)
    ->ArgPair(0, 100)
    ->ArgPair(0, 1000)
    ->ArgPair(0, 10000);

static void EVENTS_add_and_gentable(benchmark::State& state) {
  auto sub = std::make_shared<BenchmarkEventSubscriber>();

  while (state.KeepRunning()) {
    for (int i = 0; i < state.range(1); i++) {
      sub->benchmarkAdd(i++);
    }

    genRows(sub.get());
  }

  sub->clearRows();
}

BENCHMARK(EVENTS_add_and_gentable)
    ->ArgPair(0, 100)
    ->ArgPair(0, 1000)
    ->ArgPair(0, 10000);
} // namespace osquery
