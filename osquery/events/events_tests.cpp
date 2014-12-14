// Copyright 2004-present Facebook. All Rights Reserved.

#include <typeinfo>

#include <gtest/gtest.h>

#include <osquery/events.h>
#include <osquery/tables.h>

namespace osquery {

class EventsTests : public ::testing::Test {
 public:
  void TearDown() { EventFactory::deregisterEventPublishers(); }
};

// The most basic event publisher uses useless Subscription/Event.
class BasicEventPublisher
    : public EventPublisher<SubscriptionContext, EventContext> {};
class AnotherBasicEventPublisher
    : public EventPublisher<SubscriptionContext, EventContext> {};

// Create some still-useless subscription and event structures.
struct FakeSubscriptionContext : SubscriptionContext {};
struct FakeEventContext : EventContext {};

// Typdef the shared_ptr accessors.
typedef std::shared_ptr<FakeSubscriptionContext> FakeSubscriptionContextRef;
typedef std::shared_ptr<FakeEventContext> FakeEventContextRef;

// Now a publisher with a type.
class FakeEventPublisher
    : public EventPublisher<FakeSubscriptionContext, FakeEventContext> {
 public:
  EventPublisherID type() { return "Fake"; }
};

class AnotherFakeEventPublisher
    : public EventPublisher<FakeSubscriptionContext, FakeEventContext> {
 public:
  EventPublisherID type() { return "AnotherFake"; }
};

TEST_F(EventsTests, test_event_pub) {
  auto pub = std::make_shared<FakeEventPublisher>();
  EXPECT_EQ(pub->type(), "Fake");

  // Test type names.
  auto pub_sub = pub->createSubscriptionContext();
  EXPECT_EQ(typeid(FakeSubscriptionContext), typeid(*pub_sub));
}

TEST_F(EventsTests, test_register_event_pub) {
  // A caller may register an event type using the class template.
  // This template class is equivilent to the reinterpret casting target.
  auto status = EventFactory::registerEventPublisher<BasicEventPublisher>();
  EXPECT_TRUE(status.ok());

  // This class is the SAME, there was no type override.
  status = EventFactory::registerEventPublisher<AnotherBasicEventPublisher>();
  EXPECT_FALSE(status.ok());

  // This class is different but also uses different types!
  status = EventFactory::registerEventPublisher<FakeEventPublisher>();
  EXPECT_TRUE(status.ok());

  // May also register the event_pub instance
  auto pub = std::make_shared<AnotherFakeEventPublisher>();
  status = EventFactory::registerEventPublisher<AnotherFakeEventPublisher>(pub);
  EXPECT_TRUE(status.ok());
}

TEST_F(EventsTests, test_create_event_pub) {
  auto status = EventFactory::registerEventPublisher<BasicEventPublisher>();
  EXPECT_TRUE(status.ok());

  // Make sure only the first event type was recorded.
  EXPECT_EQ(EventFactory::numEventPublishers(), 1);
}

TEST_F(EventsTests, test_create_subscription) {
  EventFactory::registerEventPublisher<BasicEventPublisher>();

  // Make sure a subscription cannot be added for a non-existent event type.
  // Note: It normally would not make sense to create a blank subscription.
  auto subscription = Subscription::create();
  auto status = EventFactory::addSubscription("Fake", subscription);
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

  EventFactory::registerEventPublisher<BasicEventPublisher>();

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
 public:
  EventPublisherID type() { return "Test"; }
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
  auto status = EventFactory::registerEventPublisher<BasicEventPublisher>();
  auto pub = std::make_shared<TestEventPublisher>();
  status = EventFactory::registerEventPublisher(pub);

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
  status = EventFactory::addSubscription("Test", sc);
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

  status = EventFactory::deregisterEventPublisher("Test");
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

Status TestTheeCallback(EventContextRef context, bool reserved) {
  kBellHathTolled += 1;
  return Status(0, "OK");
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
  return RUN_ALL_TESTS();
}
