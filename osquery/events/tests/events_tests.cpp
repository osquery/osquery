/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/filesystem/operations.hpp>

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/events.h>
#include <osquery/tables.h>

namespace osquery {

class EventsTests : public ::testing::Test {
 public:
  void SetUp() override {
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
  auto pub = std::make_shared<FakeEventPublisher>();
  EXPECT_EQ(pub->type(), "FakePublisher");

  // Test type names.
  auto pub_sub = pub->createSubscriptionContext();
  EXPECT_EQ(typeid(FakeSubscriptionContext), typeid(*pub_sub));
}

TEST_F(EventsTests, test_register_event_publisher) {
  auto basic_pub = std::make_shared<BasicEventPublisher>();
  auto status = EventFactory::registerEventPublisher(basic_pub);

  // This class is the SAME, there was no type override.
  auto another_basic_pub = std::make_shared<AnotherBasicEventPublisher>();
  status = EventFactory::registerEventPublisher(another_basic_pub);
  EXPECT_FALSE(status.ok());

  // This class is different but also uses different types!
  auto fake_pub = std::make_shared<FakeEventPublisher>();
  status = EventFactory::registerEventPublisher(fake_pub);
  EXPECT_TRUE(status.ok());

  // May also register the event_pub instance
  auto another_fake_pub = std::make_shared<AnotherFakeEventPublisher>();
  status = EventFactory::registerEventPublisher(another_fake_pub);
  EXPECT_TRUE(status.ok());
}

TEST_F(EventsTests, test_event_publisher_types) {
  auto pub = std::make_shared<FakeEventPublisher>();
  EXPECT_EQ(pub->type(), "FakePublisher");

  EventFactory::registerEventPublisher(pub);
  auto pub2 = EventFactory::getEventPublisher("FakePublisher");
  EXPECT_EQ(pub->type(), pub2->type());
}

TEST_F(EventsTests, test_duplicate_event_publisher) {
  auto pub = std::make_shared<BasicEventPublisher>();
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
}

TEST_F(EventsTests, test_create_subscription) {
  auto pub = std::make_shared<BasicEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  // Make sure a subscription cannot be added for a non-existent event type.
  // Note: It normally would not make sense to create a blank subscription.
  auto subscription = Subscription::create("FakeSubscriber");
  auto status = EventFactory::addSubscription("FakePublisher", subscription);
  EXPECT_FALSE(status.ok());

  // In this case we can still add a blank subscription to an existing event
  // type.
  status = EventFactory::addSubscription("publisher", subscription);
  EXPECT_TRUE(status.ok());

  // Make sure the subscription is added.
  EXPECT_EQ(EventFactory::numSubscriptions("publisher"), 1U);
}

TEST_F(EventsTests, test_multiple_subscriptions) {
  Status status;

  auto pub = std::make_shared<BasicEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  auto subscription = Subscription::create("subscriber");
  status = EventFactory::addSubscription("publisher", subscription);
  status = EventFactory::addSubscription("publisher", subscription);

  EXPECT_EQ(EventFactory::numSubscriptions("publisher"), 2U);
}

struct TestSubscriptionContext : public SubscriptionContext {
  int smallest;
};

class TestEventPublisher
    : public EventPublisher<TestSubscriptionContext, EventContext> {
  DECLARE_PUBLISHER("TestPublisher");

 public:
  Status setUp() override {
    smallest_ever_ += 1;
    return Status(0, "OK");
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
  EventFactory::registerEventPublisher(basic_pub);
  auto pub = std::make_shared<TestEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);

  // These event types have unique event type IDs
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(EventFactory::numEventPublishers(), 2U);

  // Make sure the setUp function was called.
  EXPECT_EQ(pub->getTestValue(), 1);
}

TEST_F(EventsTests, test_custom_subscription) {
  // Step 1, register event type
  auto pub = std::make_shared<TestEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);

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
}

TEST_F(EventsTests, test_tear_down) {
  auto pub = std::make_shared<TestEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);

  // Make sure set up incremented the test value.
  EXPECT_EQ(pub->getTestValue(), 1);

  status = EventFactory::deregisterEventPublisher("TestPublisher");
  EXPECT_TRUE(status.ok());

  // Make sure tear down inremented the test value.
  EXPECT_EQ(pub->getTestValue(), 2);

  // Once more, now deregistering all event types.
  status = EventFactory::registerEventPublisher(pub);
  EXPECT_EQ(pub->getTestValue(), 3);
  EventFactory::end();
  EXPECT_EQ(pub->getTestValue(), 4);

  // Make sure the factory state represented.
  EXPECT_EQ(EventFactory::numEventPublishers(), 0U);
}

static int kBellHathTolled = 0;

Status TestTheeCallback(const EventContextRef& ec,
                        const SubscriptionContextRef& sc) {
  kBellHathTolled += 1;
  return Status(0, "OK");
}

class FakeEventSubscriber : public EventSubscriber<FakeEventPublisher> {
 public:
  bool bellHathTolled{false};
  bool contextBellHathTolled{false};
  bool shouldFireBethHathTolled{false};
  size_t timesConfigured{0};

  FakeEventSubscriber() {
    setName("FakeSubscriber");
  }

  void configure() override {
    timesConfigured++;
  }

  Status Callback(const ECRef& ec, const SCRef& sc) {
    // We don't care about the subscription or the event contexts.
    bellHathTolled = true;
    return Status(0, "OK");
  }

  Status SpecialCallback(const ECRef& ec, const SCRef& sc) {
    // Now we care that the event context is corrected passed.
    if (ec->required_value == 42) {
      contextBellHathTolled = true;
    }
    return Status(0, "OK");
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
};

TEST_F(EventsTests, test_event_subscriber) {
  auto sub = std::make_shared<FakeEventSubscriber>();
  EXPECT_EQ(sub->getType(), "FakePublisher");
  EXPECT_EQ(sub->getName(), "FakeSubscriber");
}

TEST_F(EventsTests, test_event_subscriber_subscribe) {
  auto pub = std::make_shared<FakeEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  auto sub = std::make_shared<FakeEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  // Don't overload the normal `init` Subscription member.
  sub->lateInit();
  pub->configure();
  EXPECT_EQ(pub->numSubscriptions(), 1U);

  auto ec = pub->createEventContext();
  pub->fire(ec, 0);

  EXPECT_TRUE(sub->bellHathTolled);
}

TEST_F(EventsTests, test_event_subscriber_context) {
  auto pub = std::make_shared<FakeEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  auto sub = std::make_shared<FakeEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  sub->laterInit();
  pub->configure();
  auto ec = pub->createEventContext();
  ec->required_value = 42;
  pub->fire(ec, 0);

  EXPECT_TRUE(sub->contextBellHathTolled);
}

TEST_F(EventsTests, test_event_subscriber_configure) {
  auto sub = std::make_shared<FakeEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);
  // Register this subscriber (within the RegistryFactory), so it receives
  // configure/reconfigure events.
  auto& rf = RegistryFactory::get();
  rf.registry("event_subscriber")->add("fake", sub);

  // Assure we start from a base state.
  EXPECT_EQ(sub->timesConfigured, 0U);
  // Force the config into a loaded state.
  Config::getInstance().loaded_ = true;
  Config::getInstance().update({{"data", "{}"}});
  EXPECT_EQ(sub->timesConfigured, 1U);

  rf.registry("event_subscriber")->remove(sub->getName());
  Config::getInstance().update({{"data", "{}"}});
  EXPECT_EQ(sub->timesConfigured, 1U);
}

TEST_F(EventsTests, test_fire_event) {
  Status status;

  auto pub = std::make_shared<BasicEventPublisher>();
  status = EventFactory::registerEventPublisher(pub);

  auto sub = std::make_shared<FakeEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  auto subscription = Subscription::create("FakeSubscriber");
  subscription->callback = TestTheeCallback;
  status = EventFactory::addSubscription("publisher", subscription);
  pub->configure();

  // The event context creation would normally happen in the event type.
  auto ec = pub->createEventContext();
  pub->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 1);

  auto second_subscription = Subscription::create("FakeSubscriber");
  status = EventFactory::addSubscription("publisher", second_subscription);
  pub->configure();

  // Now there are two subscriptions (one sans callback).
  pub->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 2);

  // Now both subscriptions have callbacks.
  second_subscription->callback = TestTheeCallback;
  pub->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 4);
}

class SubFakeEventSubscriber : public FakeEventSubscriber {
 public:
  SubFakeEventSubscriber() {
    setName("SubFakeSubscriber");
  }

 private:
  FRIEND_TEST(EventsTests, test_subscriber_names);
};

TEST_F(EventsTests, test_subscriber_names) {
  auto pub = std::make_shared<BasicEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  auto subsub = std::make_shared<SubFakeEventSubscriber>();
  EXPECT_EQ(subsub->getType(), "FakePublisher");
  EXPECT_EQ(subsub->getName(), "SubFakeSubscriber");
  EXPECT_EQ(subsub->dbNamespace(), "FakePublisher.SubFakeSubscriber");

  auto sub = std::make_shared<FakeEventSubscriber>();
  EXPECT_EQ(sub->getName(), "FakeSubscriber");
  EXPECT_EQ(sub->dbNamespace(), "FakePublisher.FakeSubscriber");
}

class DisabledEventSubscriber : public EventSubscriber<FakeEventPublisher> {
 public:
  DisabledEventSubscriber() : EventSubscriber(false) {}
};

TEST_F(EventsTests, test_event_toggle_subscribers) {
  // Make sure subscribers can disable themselves using the event subscriber
  // constructor parameter.
  auto sub = std::make_shared<DisabledEventSubscriber>();
  EXPECT_TRUE(sub->disabled);
  // Normal subscribers will be enabled.
  auto sub2 = std::make_shared<SubFakeEventSubscriber>();
  EXPECT_FALSE(sub2->disabled);

  // Registering a disabled subscriber will put it into a paused state.
  EventFactory::registerEventSubscriber(sub);
  EXPECT_EQ(sub->state(), EventState::EVENT_PAUSED);
}
}
