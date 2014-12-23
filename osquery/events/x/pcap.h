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

#include <arpa/inet.h>
#include <pcap.h>

#include <osquery/events.h>
#include <osquery/status.h>

namespace osquery {

/**
 * @brief Define a small namespace for PCAP header structures.
 */
namespace pcap {
#define PCAP_IP_PROTOCOL_TCP 6
#define PCAP_IP_PROTOCOL_UDP 17
#define PCAP_IP_PROTOCOL_ICMP 1
#define PCAP_IP_MIN_HDR_LEN 20
#define PCAP_IP6_HDR_LEN 40
#define PCAP_TCP_MIN_HDR_LEN 20
#define PCAP_UDP_HDR_LEN 8

#define PCAP_ETHER_ADDR_LEN 6
#define PCAP_ETHER_HDR_LEN 14

/// PCAP Ethernet header.
typedef struct ethernet {
  u_char ether_dhost[PCAP_ETHER_ADDR_LEN];
  u_char ether_shost[PCAP_ETHER_ADDR_LEN];
  u_short ether_type;
#define PCAP_ETHER_TYPE_IP 0x0800
#define PCAP_ETHER_TYPE_ARP 0x0806
#define PCAP_ETHER_TYPE_IP6 0x86DD
#define PCAP_ETHER_TYPE_8021X 0x888E
} ethernet;

/// PCAP IP header.
typedef struct ip {
  // IP header version << 4 | header length >> 2.
  u_char ip_vhl;
  u_char ip_tos;
  u_short ip_len;
  u_short ip_id;
  u_short ip_off;
  u_char ip_ttl;
  u_char ip_protocol;
  u_short ip_checksum;
  struct in_addr ip_src;
  struct in_addr ip_dst;
} ip;

typedef struct ip6 {
  u_int ip_version_class_flow;
  u_short ip_len;
  u_char ip_protocol;
  u_char ip_ttl;
  u_char ip_src[16];
  u_char ip_dst[16];
} ip6;

#define PCAP_IP_HL(vhl) ((vhl)&0x0f)
#define PCAP_IP_V(vhl) ((vhl) >> 4)

  typedef u_int tcp_seq;

  // PCAP TCP header.
  typedef struct tcp {
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
#define PCAP_TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define PCAP_TH_FIN 0x01
#define PCAP_TH_SYN 0x02
#define PCAP_TH_RST 0x04
#define PCAP_TH_PUSH 0x08
#define PCAP_TH_ACK 0x10
#define PCA_TH_URG 0x20
#define PCAP_TH_ECE 0x40
#define PCAP_TH_CWR 0x80
#define PCAP_TH_FLAGS \
  (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win;
    u_short th_checksum;
    u_short th_urp;
  } tcp;

  typedef struct udp {
    u_short th_sport;
    u_short th_dport;
    u_short th_legnth;
    u_short th_checksum;
  } udp;

  typedef union {
    struct udp udp;
    struct tcp tcp;
  } transport;
}

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
  const struct pcap_pkthdr *header;
  const u_char *packet;
  const pcap::ethernet *ethernet;
  const pcap::ip *ip;
  const pcap::ip6 *ip6;
  const pcap::transport *transport;
  const u_char *payload;
  size_t payload_length;

  /// Parsed packet details.
  u_short network_protocol;
  u_char transport_protocol;
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
