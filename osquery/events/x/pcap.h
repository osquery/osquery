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
#define ETHER_ADDR_LEN  6
#define ETHER_HDR_LEN 14

  /* Ethernet header */
  struct ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
  };

  /* IP header */
  struct ip {
    u_char ip_vhl;    /* version << 4 | header length >> 2 */
    u_char ip_tos;    /* type of service */
    u_short ip_len;   /* total length */
    u_short ip_id;    /* identification */
    u_short ip_off;   /* fragment offset field */
  #define IP_RF 0x8000    /* reserved fragment flag */
  #define IP_DF 0x4000    /* dont fragment flag */
  #define IP_MF 0x2000    /* more fragments flag */
  #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    u_char ip_ttl;    /* time to live */
    u_char ip_p;    /* protocol */
    u_short ip_sum;   /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
  };
  #define IP_HL(ip)   (((ip)->ip_vhl) & 0x0f)
  #define IP_V(ip)    (((ip)->ip_vhl) >> 4)

  /* TCP header */
  typedef u_int tcp_seq;

  struct tcp {
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;   /* sequence number */
    tcp_seq th_ack;   /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
  #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
  #define TH_FIN 0x01
  #define TH_SYN 0x02
  #define TH_RST 0x04
  #define TH_PUSH 0x08
  #define TH_ACK 0x10
  #define TH_URG 0x20
  #define TH_ECE 0x40
  #define TH_CWR 0x80
  #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;   /* window */
    u_short th_sum;   /* checksum */
    u_short th_urp;   /* urgent pointer */
  };
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
