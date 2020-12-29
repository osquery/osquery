/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem/operations.hpp>

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/events/eventpublisher.h>
#include <osquery/events/events.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/info/tool_type.h>

namespace osquery {

class EventsTests : public ::testing::Test {
 protected:
  void SetUp() override {
    setToolType(ToolType::TEST);
    registryAndPluginInit();
    initDatabasePluginForTesting();

    RegistryFactory::get().registry("config_parser")->setUp();
  }
  void TearDown() override {
    EventFactory::end(true);
  }
};

// The most basic event publisher uses useless Subscription/Event.
class BasicEventPublisher
    : public EventPublisher<SubscriptionContext, EventContext> {};

class AnotherBasicEventPublisher
    : public EventPublisher<SubscriptionContext, EventContext> {};

// Create some semi-useless subscription and event structures.
struct FakeSubscriptionContext : SubscriptionContext {
  int require_this_value;
};

struct FakeEventContext : EventContext {
  int required_value;
};

// Typedef the shared_ptr accessors.
using FakeSubscriptionContextRef = std::shared_ptr<FakeSubscriptionContext>;
using FakeEventContextRef = std::shared_ptr<FakeEventContext>;

// Now a publisher with a type.
class FakeEventPublisher
    : public EventPublisher<FakeSubscriptionContext, FakeEventContext> {
  DECLARE_PUBLISHER("FakePublisher");
};

class AnotherFakeEventPublisher
    : public EventPublisher<FakeSubscriptionContext, FakeEventContext> {
  DECLARE_PUBLISHER("AnotherFakePublisher");
};

TEST_F(EventsTests, test_event_publisher) {
  // Inspect the publisher "type", which is the publisher "name".
  auto pub = std::make_shared<FakeEventPublisher>();
  EXPECT_EQ(pub->type(), "FakePublisher");
  EXPECT_EQ(EventFactory::getType<FakeEventPublisher>(), "FakePublisher");
  // This is different for each publisher with an overridden type().
  EXPECT_EQ(EventFactory::getType<AnotherFakeEventPublisher>(),
            "AnotherFakePublisher");

  // Test type names.
  auto pub_sub = pub->createSubscriptionContext();
  EXPECT_EQ(typeid(FakeSubscriptionContext), typeid(*pub_sub));

  // This publisher has no type.
  auto basic_pub = std::make_shared<BasicEventPublisher>();
  EXPECT_TRUE(basic_pub->type().empty());
  EXPECT_TRUE(EventFactory::getType<BasicEventPublisher>().empty());
  basic_pub->setName("BasicPublisher");
  EXPECT_EQ(basic_pub->type(), "BasicPublisher");
}

TEST_F(EventsTests, test_register_event_publisher) {
  auto basic_pub = std::make_shared<BasicEventPublisher>();
  auto status = EventFactory::registerEventPublisher(basic_pub);
  // This publisher has no type set, registration will fail.
  EXPECT_FALSE(status.ok());

  // Set a name for the publisher, which becomes the type by default.
  basic_pub->setName("BasicPublisher");
  status = EventFactory::registerEventPublisher(basic_pub);
  EXPECT_TRUE(status.ok());

  // This class is the SAME, there was no type override.
  auto another_basic_pub = std::make_shared<AnotherBasicEventPublisher>();
  another_basic_pub->setName(basic_pub->getName());
  status = EventFactory::registerEventPublisher(another_basic_pub);
  EXPECT_FALSE(status.ok());

  // This class is different but also uses different types!
  auto fake_pub = std::make_shared<FakeEventPublisher>();
  status = EventFactory::registerEventPublisher(fake_pub);
  EXPECT_TRUE(status.ok());

  // May also register a similar (same EC, SC), but different publisher.
  auto another_fake_pub = std::make_shared<AnotherFakeEventPublisher>();
  status = EventFactory::registerEventPublisher(another_fake_pub);
  EXPECT_TRUE(status.ok());

  status = EventFactory::deregisterEventPublisher(basic_pub->type());
  EXPECT_TRUE(status.ok());
  status = EventFactory::deregisterEventPublisher(fake_pub->type());
  EXPECT_TRUE(status.ok());
  status = EventFactory::deregisterEventPublisher(another_fake_pub->type());
  EXPECT_TRUE(status.ok());

  // Attempting to deregister a publisher a second time.
  status = EventFactory::deregisterEventPublisher(another_fake_pub->type());
  EXPECT_FALSE(status.ok());

  // Attempting to deregister a publish that failed registering.
  status = EventFactory::deregisterEventPublisher(another_basic_pub->type());
  EXPECT_FALSE(status.ok());
}

TEST_F(EventsTests, test_event_publisher_types) {
  auto pub = std::make_shared<FakeEventPublisher>();
  EXPECT_EQ(pub->type(), "FakePublisher");

  auto status = EventFactory::registerEventPublisher(pub);
  ASSERT_TRUE(status.ok());
  auto pub2 = EventFactory::getEventPublisher("FakePublisher");
  EXPECT_EQ(pub->type(), pub2->type());

  // It is possible to deregister by base event publisher type.
  status = EventFactory::deregisterEventPublisher(pub2);
  EXPECT_TRUE(status.ok());
  // And attempting to deregister by type afterward will fail.
  status = EventFactory::deregisterEventPublisher(pub->type());
  EXPECT_FALSE(status.ok());
}

TEST_F(EventsTests, test_duplicate_event_publisher) {
  auto pub = std::make_shared<BasicEventPublisher>();
  pub->setName("BasicPublisher");
  auto status = EventFactory::registerEventPublisher(pub);
  EXPECT_TRUE(status.ok());

  // Make sure only the first event type was recorded.
  EXPECT_EQ(EventFactory::numEventPublishers(), 1U);
}

class UniqueEventPublisher
    : public EventPublisher<FakeSubscriptionContext, FakeEventContext> {
  DECLARE_PUBLISHER("unique");
};

TEST_F(EventsTests, test_create_using_registry) {
  // The events API uses attachEvents to move registry event publishers and
  // subscribers into the events factory.
  EXPECT_EQ(EventFactory::numEventPublishers(), 0U);
  attachEvents();

  // Store the number of default event publishers (in core).
  size_t default_publisher_count = EventFactory::numEventPublishers();

  auto& rf = RegistryFactory::get();
  // Now add another registry item, but do not yet attach it.
  rf.registry("event_publisher")
      ->add("unique", std::make_shared<UniqueEventPublisher>());
  EXPECT_EQ(EventFactory::numEventPublishers(), default_publisher_count);

  // Now attach and make sure it was added.
  attachEvents();
  EXPECT_EQ(EventFactory::numEventPublishers(), default_publisher_count + 1U);

  auto status = EventFactory::deregisterEventPublisher("unique");
  EXPECT_TRUE(status.ok());
}

TEST_F(EventsTests, test_create_subscription) {
  std::string basic_publisher_type = "BasicPublisher";

  auto pub = std::make_shared<BasicEventPublisher>();
  pub->setName(basic_publisher_type);
  auto status = EventFactory::registerEventPublisher(pub);
  ASSERT_TRUE(status.ok());

  // Make sure a subscription cannot be added for a non-existent event type.
  // Note: It normally would not make sense to create a blank subscription.
  auto subscription = Subscription::create("FakeSubscriber");
  status = EventFactory::addSubscription("FakePublisher", subscription);
  EXPECT_FALSE(status.ok());

  // In this case we can still add a blank subscription to an existing event
  // type.
  status = EventFactory::addSubscription(basic_publisher_type, subscription);
  EXPECT_TRUE(status.ok());

  // Make sure the subscription is added.
  EXPECT_EQ(EventFactory::numSubscriptions(basic_publisher_type), 1U);

  status = EventFactory::deregisterEventPublisher(basic_publisher_type);
  EXPECT_TRUE(status.ok());
}

TEST_F(EventsTests, test_multiple_subscriptions) {
  std::string basic_publisher_type = "BasicPublisher";

  auto pub = std::make_shared<BasicEventPublisher>();
  pub->setName(basic_publisher_type);
  auto status = EventFactory::registerEventPublisher(pub);
  ASSERT_TRUE(status.ok());

  auto subscription = Subscription::create("subscriber");
  status = EventFactory::addSubscription(basic_publisher_type, subscription);
  status = EventFactory::addSubscription(basic_publisher_type, subscription);
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(EventFactory::numSubscriptions(basic_publisher_type), 2U);

  status = EventFactory::deregisterEventPublisher(basic_publisher_type);
  EXPECT_TRUE(status.ok());
}

struct TestSubscriptionContext : public SubscriptionContext {
  int smallest{0};
};

class TestEventPublisher
    : public EventPublisher<TestSubscriptionContext, EventContext> {
  DECLARE_PUBLISHER("TestPublisher");

 public:
  Status setUp() override {
    smallest_ever_ += 1;
    return Status::success();
  }

  void configure() override {
    int smallest_subscription = smallest_ever_;

    configure_run = true;
    for (const auto& subscription : subscriptions_) {
      auto subscription_context = getSubscriptionContext(subscription->context);
      if (smallest_subscription > subscription_context->smallest) {
        smallest_subscription = subscription_context->smallest;
      }
    }

    smallest_ever_ = smallest_subscription;
  }

  void tearDown() override {
    smallest_ever_ += 1;
  }

  // Custom methods do not make sense, but for testing it exists.
  int getTestValue() {
    return smallest_ever_;
  }

 public:
  bool configure_run{false};

 private:
  int smallest_ever_{0};
};

TEST_F(EventsTests, test_create_custom_event_publisher) {
  auto basic_pub = std::make_shared<BasicEventPublisher>();
  basic_pub->setName("BasicPublisher");
  auto status = EventFactory::registerEventPublisher(basic_pub);
  ASSERT_TRUE(status.ok());

  auto pub = std::make_shared<TestEventPublisher>();
  status = EventFactory::registerEventPublisher(pub);
  ASSERT_TRUE(status.ok());

  // These event types have unique event type IDs
  EXPECT_EQ(EventFactory::numEventPublishers(), 2U);

  // Make sure the setUp function was called.
  EXPECT_EQ(pub->getTestValue(), 1);

  status = EventFactory::deregisterEventPublisher(pub->type());
  EXPECT_TRUE(status.ok());
  status = EventFactory::deregisterEventPublisher(basic_pub->type());
  EXPECT_TRUE(status.ok());
}

TEST_F(EventsTests, test_custom_subscription) {
  // Step 1, register event type
  auto pub = std::make_shared<TestEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);
  ASSERT_TRUE(status.ok());

  // Step 2, create and configure a subscription context
  auto sc = std::make_shared<TestSubscriptionContext>();
  sc->smallest = -1;

  // Step 3, add the subscription to the event type
  status = EventFactory::addSubscription("TestPublisher", "TestSubscriber", sc);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(pub->numSubscriptions(), 1U);
  // Run configure on this publisher.
  pub->configure();

  // The event type must run configure for each added subscription.
  EXPECT_TRUE(pub->configure_run);
  EXPECT_EQ(pub->getTestValue(), -1);

  status = EventFactory::deregisterEventPublisher(pub->type());
  EXPECT_TRUE(status.ok());
}

TEST_F(EventsTests, test_tear_down) {
  auto pub = std::make_shared<TestEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);
  ASSERT_TRUE(status.ok());

  // Make sure set up incremented the test value.
  EXPECT_EQ(pub->getTestValue(), 1);

  status = EventFactory::deregisterEventPublisher(pub->type());
  EXPECT_TRUE(status.ok());

  // Make sure tear down incremented the test value.
  EXPECT_EQ(pub->getTestValue(), 2);

  // Once more, now deregistering all event types.
  status = EventFactory::registerEventPublisher(pub);
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(pub->getTestValue(), 3);
  EventFactory::end();
  EXPECT_EQ(pub->getTestValue(), 4);

  // Make sure the factory state represented.
  EXPECT_EQ(EventFactory::numEventPublishers(), 0U);

  // Implicit deregister due to end of event factory.
  status = EventFactory::deregisterEventPublisher(pub->type());
  EXPECT_FALSE(status.ok());
}

static int kBellHathTolled = 0;

Status TestTheeCallback(const EventContextRef& ec,
                        const SubscriptionContextRef& sc) {
  kBellHathTolled += 1;
  return Status::success();
}

class FakeEventSubscriber : public EventSubscriber<FakeEventPublisher> {
 public:
  bool bellHathTolled{false};
  bool contextBellHathTolled{false};
  bool shouldFireBethHathTolled{false};
  size_t timesConfigured{0};

  FakeEventSubscriber() {
    setName("fake_events");
  }

  explicit FakeEventSubscriber(bool skip_name) {
    if (!skip_name) {
      FakeEventSubscriber();
    }
  }

  void configure() override {
    timesConfigured++;
  }

  Status Callback(const ECRef& ec, const SCRef& sc) {
    // We don't care about the subscription or the event contexts.
    bellHathTolled = true;
    return Status::success();
  }

  Status SpecialCallback(const ECRef& ec, const SCRef& sc) {
    // Now we care that the event context is corrected passed.
    if (ec->required_value == 42) {
      contextBellHathTolled = true;
    }
    return Status::success();
  }

  void lateInit() {
    auto sub_ctx = createSubscriptionContext();
    subscribe(&FakeEventSubscriber::Callback, sub_ctx);
  }

  void laterInit() {
    auto sub_ctx = createSubscriptionContext();
    sub_ctx->require_this_value = 42;
    subscribe(&FakeEventSubscriber::SpecialCallback, sub_ctx);
  }

 private:
  FRIEND_TEST(EventsTests, test_subscriber_names);
  FRIEND_TEST(EventsTests, test_event_subscriber_configure);
};

TEST_F(EventsTests, test_event_subscriber) {
  auto sub = std::make_shared<FakeEventSubscriber>();
  EXPECT_EQ(sub->getType(), "FakePublisher");
  EXPECT_EQ(sub->getName(), "fake_events");
}

TEST_F(EventsTests, test_event_subscriber_subscribe) {
  auto pub = std::make_shared<FakeEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);
  ASSERT_TRUE(status.ok());

  auto sub = std::make_shared<FakeEventSubscriber>();
  status = EventFactory::registerEventSubscriber(sub);
  ASSERT_TRUE(status.ok());

  // Don't overload the normal `init` Subscription member.
  sub->lateInit();
  pub->configure();
  EXPECT_EQ(pub->numSubscriptions(), 1U);

  auto ec = pub->createEventContext();
  pub->fire(ec, 0);
  EXPECT_TRUE(sub->bellHathTolled);

  sub->bellHathTolled = false;
  EventFactory::fire<FakeEventPublisher>(ec);
  EXPECT_TRUE(sub->bellHathTolled);

  status = EventFactory::deregisterEventSubscriber(sub->getName());
  EXPECT_TRUE(status.ok());
  status = EventFactory::deregisterEventPublisher(pub->type());
  EXPECT_TRUE(status.ok());
}

TEST_F(EventsTests, test_event_subscriber_context) {
  auto pub = std::make_shared<FakeEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);
  ASSERT_TRUE(status.ok());

  auto sub = std::make_shared<FakeEventSubscriber>();
  status = EventFactory::registerEventSubscriber(sub);
  ASSERT_TRUE(status.ok());

  sub->laterInit();
  pub->configure();
  auto ec = pub->createEventContext();
  ec->required_value = 42;
  pub->fire(ec, 0);

  EXPECT_TRUE(sub->contextBellHathTolled);

  status = EventFactory::deregisterEventSubscriber(sub->getName());
  EXPECT_TRUE(status.ok());
  status = EventFactory::deregisterEventPublisher(pub->type());
  EXPECT_TRUE(status.ok());
}

TEST_F(EventsTests, test_event_subscriber_configure) {
  auto sub = std::make_shared<FakeEventSubscriber>();
  // Register this subscriber (within the RegistryFactory), so it receives
  // configure/reconfigure events.
  auto& rf = RegistryFactory::get();
  rf.registry("event_subscriber")->add("fake_events", sub);

  // Register it within the event factory too.
  auto status = EventFactory::registerEventSubscriber(sub);
  EXPECT_TRUE(status.ok());

  // Assure we start from a base state.
  EXPECT_EQ(sub->timesConfigured, 0U);
  // Force the config into a loaded state.
  Config::get().loaded_ = true;
  Config::get().update({{"data", "{}"}});
  EXPECT_EQ(sub->timesConfigured, 1U);

  // Now update the config to contain sets of scheduled queries.
  Config::get().update(
      {{"data",
        "{\"schedule\": {\"1\": {\"query\": \"select * from fake_events\", "
        "\"interval\": 10}, \"2\":{\"query\": \"select * from time, "
        "fake_events\", \"interval\": 19}, \"3\":{\"query\": \"select * "
        "from fake_events, fake_events\", \"interval\": 5}}}"}});

  // This will become 19 * 3, rounded up 60.
  EXPECT_EQ(sub->min_expiration_, 60U);
  EXPECT_EQ(sub->query_count_, 3U);

  // Register it within the event factory too.
  EventFactory::deregisterEventSubscriber(sub->getName());
  rf.registry("event_subscriber")->remove(sub->getName());

  // Final check to make sure updates are not effecting this subscriber.
  Config::get().update({{"data", "{}"}});
  EXPECT_EQ(sub->timesConfigured, 2U);
}

TEST_F(EventsTests, test_fire_event) {
  auto pub = std::make_shared<BasicEventPublisher>();
  pub->setName("BasicPublisher");
  auto status = EventFactory::registerEventPublisher(pub);
  ASSERT_TRUE(status.ok());

  auto sub = std::make_shared<FakeEventSubscriber>();
  status = EventFactory::registerEventSubscriber(sub);
  ASSERT_TRUE(status.ok());

  auto subscription = Subscription::create("fake_events");
  subscription->callback = TestTheeCallback;
  status = EventFactory::addSubscription("BasicPublisher", subscription);
  ASSERT_TRUE(status.ok());

  pub->configure();

  // The event context creation would normally happen in the event type.
  auto ec = pub->createEventContext();
  pub->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 1);

  auto second_subscription = Subscription::create("fake_events");
  status = EventFactory::addSubscription("BasicPublisher", second_subscription);
  ASSERT_TRUE(status.ok());

  pub->configure();

  // Now there are two subscriptions (one sans callback).
  pub->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 2);

  // Now both subscriptions have callbacks.
  second_subscription->callback = TestTheeCallback;
  pub->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 4);

  status = EventFactory::deregisterEventSubscriber(sub->getName());
  EXPECT_TRUE(status.ok());

  status = EventFactory::deregisterEventPublisher(pub->type());
  EXPECT_TRUE(status.ok());
}

class SubFakeEventSubscriber : public FakeEventSubscriber {
 public:
  SubFakeEventSubscriber() : FakeEventSubscriber(true) {
    setName("sub_fake_events");
  }

 private:
  FRIEND_TEST(EventsTests, test_subscriber_names);
};

TEST_F(EventsTests, test_subscriber_names) {
  auto subsub = std::make_shared<SubFakeEventSubscriber>();
  EXPECT_EQ(subsub->getType(), "FakePublisher");
  EXPECT_EQ(subsub->getName(), "sub_fake_events");
  EXPECT_EQ(subsub->dbNamespace(), "FakePublisher.sub_fake_events");

  auto sub = std::make_shared<FakeEventSubscriber>();
  EXPECT_EQ(sub->getName(), "fake_events");
  EXPECT_EQ(sub->dbNamespace(), "FakePublisher.fake_events");
}

class DisabledEventSubscriber : public EventSubscriber<FakeEventPublisher> {
 public:
  DisabledEventSubscriber() : EventSubscriber(false) {}
};

TEST_F(EventsTests, test_event_toggle_subscribers) {
  // Make sure subscribers can disable themselves using the event subscriber
  // constructor parameter.
  auto sub = std::make_shared<DisabledEventSubscriber>();
  sub->setName("disabled_events");
  EXPECT_TRUE(sub->disabled);

  // Normal subscribers will be enabled.
  auto sub2 = std::make_shared<SubFakeEventSubscriber>();
  EXPECT_FALSE(sub2->disabled);

  // Registering a disabled subscriber will put it into a paused state.
  auto status = EventFactory::registerEventSubscriber(sub);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(sub->state(), EventState::EVENT_PAUSED);

  status = EventFactory::deregisterEventSubscriber(sub->getName());
  EXPECT_TRUE(status.ok());
}
} // namespace osquery
