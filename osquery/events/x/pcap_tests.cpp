/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/events.h>
#include <osquery/tables.h>

#include "osquery/events/x/pcap.h"

namespace osquery {

class PcapTests : public testing::Test {
 protected:
  void SetUp() {
    Flag::get().updateValue("event_pubsub_network", "1");
  }
  void TearDown() { EventFactory::deregisterEventPublishers(); }
};

TEST_F(PcapTests, test_pcap_register) {
  // Assume event type is registered.
  auto pub = std::make_shared<PcapEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);

  EXPECT_TRUE(status.ok());
  EXPECT_EQ(EventFactory::numEventPublishers(), 1);
}

TEST_F(PcapTests, test_pcap_interface_default) {
  auto pub = std::make_shared<PcapEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);

  // Get a default ctor subscriber.
  auto sc = pub->createSubscriptionContext();

  // Make sure the scription was added.
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  EXPECT_EQ(pub->aggregate_interface_, "default");
}

TEST_F(PcapTests, test_pcap_interface_any) {
  auto pub = std::make_shared<PcapEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);

  // Now the context is for any interface.
  auto sc = pub->createSubscriptionContext();
  sc->interface = "any";
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  EXPECT_EQ(pub->aggregate_interface_, "any");

  // Now add a second subscription for another interface.
  sc = pub->createSubscriptionContext();
  sc->interface = "some_other_interface0";
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  // Make sure the interface remains any.
  EXPECT_EQ(pub->aggregate_interface_, "any");
}

TEST_F(PcapTests, test_pcap_interface_multiple) {
  auto pub = std::make_shared<PcapEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);

  // Interface is non-meta.
  auto sc = pub->createSubscriptionContext();
  sc->interface = "interface_0";
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  EXPECT_EQ(pub->aggregate_interface_, "interface_0");

  // TODO(reed): The interface should now become 'any'.
  sc = pub->createSubscriptionContext();
  sc->interface = "interface_1";
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  EXPECT_EQ(pub->aggregate_interface_, "any");
}

TEST_F(PcapTests, test_pcap_promiscuous) {
  auto pub = std::make_shared<PcapEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);
  auto sc = pub->createSubscriptionContext();

  // Assure the default value for promiscuous remains.
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  EXPECT_EQ(pub->promiscuous_, 0);

  // Make sure the value converges to true = 1.
  sc = pub->createSubscriptionContext();
  sc->promiscuous = true;
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  EXPECT_EQ(pub->promiscuous_, 1);
}

TEST_F(PcapTests, test_pcap_length) {
  auto pub = std::make_shared<PcapEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);
  auto sc = pub->createSubscriptionContext();

  // Assure the default value for publisher snap length.
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  EXPECT_EQ(pub->length_, kPcapPublisherDefaultLength);

  // Make sure the length converges on the max.
  sc = pub->createSubscriptionContext();
  sc->length = kPcapPublisherDefaultLength + 1;
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  EXPECT_EQ(pub->length_, kPcapPublisherDefaultLength + 1);

  // If a 0 length is provided the length changes to MAX.
  sc = pub->createSubscriptionContext();
  sc->length = 0;
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  EXPECT_EQ(pub->length_, BUFSIZ);
}

TEST_F(PcapTests, test_pcap_filter) {
  auto pub = std::make_shared<PcapEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);
  auto sc = pub->createSubscriptionContext();

  // Make sure the scription was added.
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  EXPECT_EQ(pub->aggregate_filter_, "");

  sc = pub->createSubscriptionContext();
  sc->filter = "port 22";
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  // Make sure the filter is wrapped in parens.
  EXPECT_EQ(pub->aggregate_filter_, "(port 22)");
}

TEST_F(PcapTests, test_pcap_filter_multiple) {
  auto pub = std::make_shared<PcapEventPublisher>();
  auto status = EventFactory::registerEventPublisher(pub);

  auto sc = pub->createSubscriptionContext();
  sc->filter = "port 22";
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));

  // Now add a second filter, they will be ORed.
  sc = pub->createSubscriptionContext();
  sc->filter = "port 21";
  status = EventFactory::addSubscription("PcapEventPublisher",
                                         Subscription::create(sc));
  EXPECT_EQ(pub->aggregate_filter_, "(port 22) OR (port 21)");
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
