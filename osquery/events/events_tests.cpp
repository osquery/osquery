// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

#include "osquery/events.h"
#include "osquery/tables.h"

namespace osquery {

class EventsTests : public testing::Test {
 public:
  void TearDown() { EventFactory::deregisterEventPublishers(); }
};

class BasicEventPublisher : public EventPublisher {
  DECLARE_EVENTPUBLISHER(BasicEventPublisher,
                         SubscriptionContext,
                         EventContext);
};

class FakeBasicEventPublisher : public EventPublisher {
  DECLARE_EVENTPUBLISHER(FakeBasicEventPublisher,
                         SubscriptionContext,
                         EventContext);
};

TEST_F(EventsTests, test_register_event_pub) {
  Status status;

  // A caller may register an event type using the class template.
  status = EventFactory::registerEventPublisher<BasicEventPublisher>();
  EXPECT_TRUE(status.ok());

  // May also register the event_pub instance
  auto event_pub_instance = std::make_shared<FakeBasicEventPublisher>();
  status = EventFactory::registerEventPublisher(event_pub_instance);
  EXPECT_TRUE(status.ok());

  // May NOT register without subclassing, enforced at compile time.
}

TEST_F(EventsTests, test_create_event_pub) {
  Status status;

  status = EventFactory::registerEventPublisher<BasicEventPublisher>();
  EXPECT_TRUE(status.ok());

  // Do not register the same event type twice.
  status = EventFactory::registerEventPublisher<BasicEventPublisher>();
  EXPECT_FALSE(status.ok());

  // Make sure only the first event type was recorded.
  EXPECT_EQ(EventFactory::numEventPublishers(), 1);
}

TEST_F(EventsTests, test_create_subscription) {
  Status status;

  EventFactory::registerEventPublisher<BasicEventPublisher>();

  // Make sure a subscription cannot be added for a non-existent event type.
  // Note: It normally would not make sense to create a blank subscription.
  auto subscription = Subscription::create();
  status =
      EventFactory::addSubscription("FakeBasicEventPublisher", subscription);
  EXPECT_FALSE(status.ok());

  // In this case we can still add a blank subscription to an existing event
  // type.
  status = EventFactory::addSubscription("BasicEventPublisher", subscription);
  EXPECT_TRUE(status.ok());

  // Make sure the subscription is added.
  EXPECT_EQ(EventFactory::numSubscriptions("BasicEventPublisher"), 1);
}

TEST_F(EventsTests, test_multiple_subscriptions) {
  Status status;

  EventFactory::registerEventPublisher<BasicEventPublisher>();

  auto subscription = Subscription::create();
  status = EventFactory::addSubscription("BasicEventPublisher", subscription);
  status = EventFactory::addSubscription("BasicEventPublisher", subscription);

  EXPECT_EQ(EventFactory::numSubscriptions("BasicEventPublisher"), 2);
}

struct TestSubscriptionContext : public SubscriptionContext {
  int smallest;
};

class TestEventPublisher : public EventPublisher {
  DECLARE_EVENTPUBLISHER(TestEventPublisher,
                         TestSubscriptionContext,
                         EventContext);

 public:
  void setUp() { smallest_ever_ += 1; }

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
  Status status;

  status = EventFactory::registerEventPublisher<BasicEventPublisher>();
  auto test_event_pub = std::make_shared<TestEventPublisher>();
  status = EventFactory::registerEventPublisher(test_event_pub);

  // These event types have unique event type IDs
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(EventFactory::numEventPublishers(), 2);

  // Make sure the setUp function was called.
  EXPECT_EQ(test_event_pub->getTestValue(), 1);
}

TEST_F(EventsTests, test_custom_subscription) {
  Status status;

  // Step 1, register event type
  auto event_pub = std::make_shared<TestEventPublisher>();
  status = EventFactory::registerEventPublisher(event_pub);

  // Step 2, create and configure a subscription context
  auto subscription_context = std::make_shared<TestSubscriptionContext>();
  subscription_context->smallest = -1;

  // Step 3, add the subscription to the event type
  status =
      EventFactory::addSubscription("TestEventPublisher", subscription_context);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(event_pub->numSubscriptions(), 1);

  // The event type must run configure for each added subscription.
  EXPECT_TRUE(event_pub->configure_run);
  EXPECT_EQ(event_pub->getTestValue(), -1);
}

TEST_F(EventsTests, test_tear_down) {
  Status status;

  auto event_pub = std::make_shared<TestEventPublisher>();
  status = EventFactory::registerEventPublisher(event_pub);

  // Make sure set up incremented the test value.
  EXPECT_EQ(event_pub->getTestValue(), 1);

  status = EventFactory::deregisterEventPublisher("TestEventPublisher");
  EXPECT_TRUE(status.ok());

  // Make sure tear down inremented the test value.
  EXPECT_EQ(event_pub->getTestValue(), 2);

  // Once more, now deregistering all event types.
  status = EventFactory::registerEventPublisher(event_pub);
  EXPECT_EQ(event_pub->getTestValue(), 3);

  status = EventFactory::deregisterEventPublishers();
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(event_pub->getTestValue(), 4);

  // Make sure the factory state represented.
  EXPECT_EQ(EventFactory::numEventPublishers(), 0);
}

static int kBellHathTolled = 0;

Status TestTheeCallback(EventContextRef context, bool reserved) {
  kBellHathTolled += 1;
  return Status(0, "OK");
}

TEST_F(EventsTests, test_fire_event) {
  Status status;

  auto event_pub = std::make_shared<BasicEventPublisher>();
  status = EventFactory::registerEventPublisher(event_pub);

  auto subscription = Subscription::create();
  subscription->callback = TestTheeCallback;
  status = EventFactory::addSubscription("BasicEventPublisher", subscription);

  // The event context creation would normally happen in the event type.
  auto ec = event_pub->createEventContext();
  event_pub->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 1);

  auto second_subscription = Subscription::create();
  status =
      EventFactory::addSubscription("BasicEventPublisher", second_subscription);

  // Now there are two subscriptions (one sans callback).
  event_pub->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 2);

  // Now both subscriptions have callbacks.
  second_subscription->callback = TestTheeCallback;
  event_pub->fire(ec, 0);
  EXPECT_EQ(kBellHathTolled, 4);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
