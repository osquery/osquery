/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <map>
#include <vector>

#include <pcap.h>

#include <osquery/events.h>
#include <osquery/status.h>

namespace osquery {

extern size_t kPcapPublisherDefaultLength;

struct PcapSubscriptionContext : public SubscriptionContext {
  /**
   * @brief Must set an interface, to bind for packets.
   *
   * Meta-options:
   *  (1) interface = "any" will bind to any.
   *  (2) interface = "default" will use libpcap to determine.
   */
  std::string interface;
  /// Should the open on the interface use promisc mode.
  bool promiscuous;
  /// The general BPF string.
  std::string filter;
  /// The snap length to capture.
  size_t length;

  PcapSubscriptionContext();
};

struct PcapEventContext : public EventContext {
  std::string interface;
  std::string filter;

  /// Packet details/raw data.
  std::shared_ptr<struct pcap_pkthdr> header;
  std::shared_ptr<const u_char> packet;
};

typedef std::shared_ptr<PcapEventContext> PcapEventContextRef;
typedef std::shared_ptr<PcapSubscriptionContext> PcapSubscriptionContextRef;

class PcapEventPublisher
    : public EventPublisher<PcapSubscriptionContext, PcapEventContext> {
  DECLARE_PUBLISHER("PcapEventPublisher");

 public:
  /// Create an `inotify` handle descriptor.
  Status setUp();
  void configure();
  /// Release the `inotify` handle descriptor.
  void tearDown();

  Status run();

  PcapEventPublisher() : EventPublisher() {
    promiscuous_ = 0;
    handle_ = nullptr;
  }

  static void callback(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet);

 private:
  bool shouldFire(const PcapSubscriptionContextRef& sc,
                  const PcapEventContextRef& ec);

 private:
  pcap_t *handle_;
  // TODO(reed): Cannot support multiple devices/threads per event publisher.
  std::string aggregate_interface_;
  std::string aggregate_filter_;
  size_t length_;
  int promiscuous_;

 private:
  FRIEND_TEST(PcapTests, test_pcap_interface_default);
  FRIEND_TEST(PcapTests, test_pcap_interface_any);
  FRIEND_TEST(PcapTests, test_pcap_interface_multiple);
  FRIEND_TEST(PcapTests, test_pcap_promiscuous);
  FRIEND_TEST(PcapTests, test_pcap_length);
  FRIEND_TEST(PcapTests, test_pcap_filter);
  FRIEND_TEST(PcapTests, test_pcap_filter_multiple);
};
}
