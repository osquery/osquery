/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <atomic>
#include <queue>
#include <random>

#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/events/events.h>
#include <osquery/events/windows/etw/etw_publisher_processes.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/events/event_utils.h>
#include <osquery/tables/events/windows/etw_process_events.h>

namespace osquery {

DECLARE_bool(enable_etw_process_events);
const char* ETW_SUBSCRIBER_NAME = "etw_process_events";
const char* ETW_PUBLISHER_NAME = kEtwProcessPublisherName.c_str();

class ETWProcessEventsTests : public testing::Test {
 public:
  void SetUp() override {
    setToolType(ToolType::TEST);
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    // Enable ETW process events
    RegistryFactory::get().registry("config_parser")->setUp();
    FLAGS_enable_etw_process_events = true;
  }
};

TEST_F(ETWProcessEventsTests, test_subscriber_exists) {
  ASSERT_TRUE(Registry::get().exists("event_subscriber", ETW_SUBSCRIBER_NAME));

  auto plugin = Registry::get().plugin("event_subscriber", ETW_SUBSCRIBER_NAME);
  auto* subscriber =
      reinterpret_cast<std::shared_ptr<EtwProcessEventSubscriber>*>(&plugin);
  EXPECT_NE(subscriber, nullptr);
}

TEST_F(ETWProcessEventsTests, test_publisher_exists) {
  ASSERT_TRUE(Registry::get().exists("event_publisher", ETW_PUBLISHER_NAME));

  auto plugin = Registry::get().plugin("event_publisher", ETW_PUBLISHER_NAME);
  auto* publisher =
      reinterpret_cast<std::shared_ptr<EtwPublisherProcesses>*>(&plugin);
  EXPECT_NE(publisher, nullptr);
}

TEST_F(ETWProcessEventsTests, test_process_event_sanity_check) {
  // Start eventing framework
  attachEvents();

  // Launching process to generate ProcessStart and ProcessStop events
  system("logman.exe query -ets > NUL");
  Sleep(4000);

  // Querying for new generated events
  std::string query =
      "select * from etw_process_events where path LIKE '%logman.exe%'";
  SQL results(query);

  // ProcessStart and ProcessStop events
  EXPECT_GE(results.rows().size(), 2U);

  // Sanity check on selected fields
  const auto& testEvent = results.rows().front();
  EXPECT_FALSE(testEvent.at("cmdline").empty());
  EXPECT_FALSE(testEvent.at("path").empty());
  EXPECT_FALSE(testEvent.at("type").empty());
  EXPECT_FALSE(testEvent.at("username").empty());
  EXPECT_GE(std::stoul(testEvent.at("session_id")), 0U);
  EXPECT_GT(std::stoul(testEvent.at("pid")), 0U);
  EXPECT_GT(std::stoul(testEvent.at("ppid")), 0U);
  EXPECT_GT(std::stoul(testEvent.at("datetime")), 0U);

  Dispatcher::instance().stopServices();
  Dispatcher::instance().joinServices();
  Dispatcher::instance().resetStopping();
}

TEST_F(ETWProcessEventsTests, test_concurrent_queue_blockwait) {
  ConcurrentQueue<unsigned int> testQueue;
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> distUint(
      0, UINT_MAX - 1);

  std::uniform_int_distribution<std::mt19937::result_type> dist999(0, 999);

  std::atomic<unsigned long long> totalEventsProduced = 0;
  std::atomic<unsigned long long> totalEventsConsumed = 0;
  std::atomic<unsigned int> nrOfThreadsProducing = 0;

  std::vector<std::thread> producerThreads;

  unsigned int randomNumberOfProducerThreads = dist999(rng);
  nrOfThreadsProducing = randomNumberOfProducerThreads;

  // Generating a random number of producer threads
  for (unsigned int i = 0; i < randomNumberOfProducerThreads; ++i) {
    producerThreads.push_back(std::thread([&]() {
      unsigned int randomNumberOfThreadsEvents = dist999(rng);
      for (unsigned int it = 0; it < randomNumberOfThreadsEvents; ++it) {
        testQueue.push(distUint(rng));
        totalEventsProduced++;
      }

      nrOfThreadsProducing--;
    }));
  }

  // Starting a single consumer thread
  std::thread consumerThread([&]() {
    while (!testQueue.empty() || nrOfThreadsProducing != 0) {
      unsigned int value = testQueue.pop();
      totalEventsConsumed++;
    }
  });

  // Waiting for threads to join
  consumerThread.join();
  for (auto& producerThread : producerThreads) {
    producerThread.join();
  }

  EXPECT_TRUE(totalEventsProduced == totalEventsConsumed)
      << "Events produced: " << totalEventsProduced
      << " - Events consumed: " << totalEventsConsumed;
}

TEST_F(ETWProcessEventsTests, test_concurrent_queue_timeout) {
  ConcurrentQueue<unsigned int> testQueue;
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> distUint(
      0, UINT_MAX - 1);

  std::uniform_int_distribution<std::mt19937::result_type> dist999(0, 999);

  std::atomic<unsigned long long> totalEventsProduced = 0;
  std::atomic<unsigned long long> totalEventsConsumed = 0;
  std::atomic<unsigned int> nrOfThreadsProducing = 0;

  std::vector<std::thread> producerThreads;

  unsigned int randomNumberOfProducerThreads = dist999(rng);
  nrOfThreadsProducing = randomNumberOfProducerThreads;

  // Generating a random number of producer threads
  for (unsigned int i = 0; i < randomNumberOfProducerThreads; ++i) {
    producerThreads.push_back(std::thread([&]() {
      unsigned int randomNumberOfThreadsEvents = dist999(rng);
      for (unsigned int it = 0; it < randomNumberOfThreadsEvents; ++it) {
        testQueue.push(distUint(rng));
        totalEventsProduced++;
      }

      nrOfThreadsProducing--;
    }));
  }

  // Starting a single consumer thread
  std::thread consumerThread([&]() {
    while (!testQueue.empty() || nrOfThreadsProducing != 0) {
      unsigned int value = 0;
      if (testQueue.popWait(value)) {
        totalEventsConsumed++;
      }
    }
  });

  // Waiting for threads to join
  consumerThread.join();
  for (auto& producerThread : producerThreads) {
    producerThread.join();
  }

  EXPECT_TRUE(totalEventsProduced == totalEventsConsumed)
      << "Events produced: " << totalEventsProduced
      << " - Events consumed: " << totalEventsConsumed;
}
} // namespace osquery
