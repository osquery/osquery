/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <typeinfo>

#include <boost/filesystem/operations.hpp>

#include <gtest/gtest.h>

#include <osquery/events.h>
#include <osquery/tables.h>

namespace osquery {

const std::string kTestingEventsDBPath = "/tmp/rocksdb-osquery-testevents";

class EventsTests : public ::testing::Test {
 public:
  void SetUp() {
    // Setup a testing DB instance
    DBHandle::getInstanceAtPath(kTestingEventsDBPath);
  }

  void TearDown() { EventFactory::deregisterEventPublishers(); }
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

// Typdef the shared_ptr accessors.
typedef std::shared_ptr<FakeSubscriptionContext> FakeSubscriptionContextRef;
typedef std::shared_ptr<FakeEventContext> FakeEventContextRef;

// Now a publisher with a type.
class FakeEventPublisher
    : public EventPublisher<FakeSubscriptionContext, FakeEventContext> {
  DECLARE_PUBLISHER("FakePublisher");
};

class AnotherFakeEventPublisher
    : public EventPublisher<FakeSubscriptionContext, FakeEventContext> {
  DECLARE_PUBLISHER("AnotherFakePublisher");
};

TEST_F(EventsTests, test_event_pub) {
  auto pub = std::make_shared<FakeEventPublisher>();
  EXPECT_EQ(pub->type(), "FakePublisher");

  // Test type names.
  auto pub_sub = pub->createSubscriptionContext();
  EXPECT_EQ(typeid(FakeSubscriptionContext), typeid(*pub_sub));
}

TEST_F(EventsTests, test_register_event_pub) {
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

TEST_F(EventsTests, test_event_pub_types) {
  auto pub = std::make_shared<FakeEventPublisher>();
  EXPECT_EQ(pub->type(), "FakePublisher");

  EventFactory::registerEventPublisher(pub);
  auto pub2 = EventFactory::getEventPublisher("FakePublisher");
  EXPECT_EQ(pub->type(), pub2->type());
}

TEST_F(EventsTests, test_create_event_pub) {
  auto pub = std::make_shared<BasicEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);
  EXPECT_TRUE(status.ok());

  // Make sure only the first event type was recorded.
  EXPECT_EQ(EventFactory::numEventPublishers(), 1);
}

class UniqueEventPublisher
    : public EventPublisher<FakeSubscriptionContext, FakeEventContext> {
  DECLARE_PUBLISHER("unique");
};

TEST_F(EventsTests, test_create_using_registry) {
  // The events API uses attachEvents to move registry event publishers and
  // subscribers into the events factory.
  EXPECT_EQ(EventFactory::numEventPublishers(), 0);
  attachEvents();

  // Store the number of default event publishers (in core).
  int default_publisher_count = EventFactory::numEventPublishers();

  // Now add another registry item, but do not yet attach it.
  auto UniqueEventPublisherRegistryItem =
      Registry::add<UniqueEventPublisher>("event_publisher", "unique");
  EXPECT_EQ(EventFactory::numEventPublishers(), default_publisher_count);

  // Now attach and make sure it was added.
  attachEvents();
  EXPECT_EQ(EventFactory::numEventPublishers(), default_publisher_count + 1);
}

TEST_F(EventsTests, test_create_subscription) {
  auto pub = std::make_shared<BasicEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  // Make sure a subscription cannot be added for a non-existent event type.
  // Note: It normally would not make sense to create a blank subscription.
  auto subscription = Subscription::create();
  auto status = EventFactory::addSubscription("FakePublisher", subscription);
  EXPECT_FALSE(status.ok());

  // In this case we can still add a blank subscription to an existing event
  // type.
  status = EventFactory::addSubscription("publisher", subscription);
  EXPECT_TRUE(status.ok());

  // Make sure the subscription is added.
  EXPECT_EQ(EventFactory::numSubscriptions("publisher"), 1);
}

TEST_F(EventsTests, test_multiple_subscriptions) {
  Status status;

  auto pub = std::make_shared<BasicEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  auto subscription = Subscription::create();
  status = EventFactory::addSubscription("publisher", subscription);
  status = EventFactory::addSubscription("publisher", subscription);

  EXPECT_EQ(EventFactory::numSubscriptions("publisher"), 2);
}

struct TestSubscriptionContext : public SubscriptionContext {
  int smallest;
};

class TestEventPublisher
    : public EventPublisher<TestSubscriptionContext, EventContext> {
  DECLARE_PUBLISHER("TestPublisher");

 public:
  Status setUp() {
    smallest_ever_ += 1;
    return Status(0, "OK");
  }

  void configure() {
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

  void tearDown() { smallest_ever_ += 1; }

  TestEventPublisher() : EventPublisher() {
    smallest_ever_ = 0;
    configure_run = false;
  }

  // Custom methods do not make sense, but for testing it exists.
  int getTestValue() { return smallest_ever_; }

 public:
  bool configure_run;

 private:
  int smallest_ever_;
};

TEST_F(EventsTests, test_create_custom_event_pub) {
  auto basic_pub = std::make_shared<BasicEventPublisher>();
  EventFactory::registerEventPublisher(basic_pub);
  auto pub = std::make_shared<TestEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);

  // These event types have unique event type IDs
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(EventFactory::numEventPublishers(), 2);

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
  status = EventFactory::addSubscription("TestPublisher", sc);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(pub->numSubscriptions(), 1);

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

  status = EventFactory::deregisterEventPublishers();
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(pub->getTestValue(), 4);

  // Make sure the factory state represented.
  EXPECT_EQ(EventFactory::numEventPublishers(), 0);
}

static int kBellHathTolled = 0;

Status TestTheeCallback(EventContextRef context) {
  kBellHathTolled += 1;
  return Status(0, "OK");
}

class FakeEventSubscriber : public EventSubscriber<FakeEventPublisher> {
  DECLARE_SUBSCRIBER("FakeSubscriber");

 public:
  bool bellHathTolled;
  bool contextBellHathTolled;
  bool shouldFireBethHathTolled;

  FakeEventSubscriber() {
    bellHathTolled = false;
    contextBellHathTolled = false;
    shouldFireBethHathTolled = false;
  }

  Status Callback(const EventContextRef& ec) {
    // We don't care about the subscription or the event contexts.
    bellHathTolled = true;
    return Status(0, "OK");
  }

  Status SpecialCallback(const FakeEventContextRef& ec) {
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
};

TEST_F(EventsTests, test_event_sub) {
  auto sub = std::make_shared<FakeEventSubscriber>();
  EXPECT_EQ(sub->type(), "FakePublisher");
  EXPECT_EQ(sub->name(), "FakeSubscriber");
}

TEST_F(EventsTests, test_event_sub_subscribe) {
  auto pub = std::make_shared<FakeEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  auto sub = std::make_shared<FakeEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  // Don't overload the normal `init` Subscription member.
  sub->lateInit();
  EXPECT_EQ(pub->numSubscriptions(), 1);

  auto ec = pub->createEventContext();
  pub->fire(ec, 0);

  EXPECT_TRUE(sub->bellHathTolled);
}

TEST_F(EventsTests, test_event_sub_context) {
  auto pub = std::make_shared<FakeEventPublisher>();
  EventFactory::registerEventPublisher(pub);

  auto sub = std::make_shared<FakeEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);

  sub->laterInit();
  auto ec = pub->createEventContext();
  ec->required_value = 42;
  pub->fire(ec, 0);

  EXPECT_TRUE(sub->contextBellHathTolled);
}

TEST_F(EventsTests, test_fire_event) {
  Status status;

  auto pub = std::make_shared<BasicEventPublisher>();
  status = EventFactory::registerEventPublisher(pub);

  auto subscription = Subscription::create();
  subscription->callback = TestTheeCallback;
  status = EventFactory::addSubscription("publisher", subscription);

  // The event context creation would normally happen in the event type.
  auto ec = pub->createEventContext();
  pub->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 1);

  auto second_subscription = Subscription::create();
  status = EventFactory::addSubscription("publisher", second_subscription);

  // Now there are two subscriptions (one sans callback).
  pub->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 2);

  // Now both subscriptions have callbacks.
  second_subscription->callback = TestTheeCallback;
  pub->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 4);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  int status = RUN_ALL_TESTS();
  boost::filesystem::remove_all(osquery::kTestingEventsDBPath);
  return status;
}
