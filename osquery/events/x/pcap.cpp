/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/join.hpp>

#include <osquery/events.h>
#include <osquery/filesystem.h>

#include "osquery/events/x/pcap.h"

namespace osquery {

DEFINE_osquery_flag(bool,
                    event_pubsub_network,
                    false,
                    "Enable network event publishers.");

REGISTER_EVENTPUBLISHER(PcapEventPublisher);

size_t kPcapPublisherDefaultLength = 100;
size_t kPcapPublisherTimeout = 100; // 60 * 1000;

PcapSubscriptionContext::PcapSubscriptionContext() {
  promiscuous = false;
  length = kPcapPublisherDefaultLength;
}

Status PcapEventPublisher::setUp() {
  // No need to setup anything, run will restart every time.
  if (!FLAGS_event_pubsub_network) {
    return Status(1, "Network event publishers are disabled.");
  }
  return Status(0, "OK");
}

void PcapEventPublisher::tearDown() {
  if (handle_ != nullptr) {
    pcap_breakloop(handle_);
    pcap_close(handle_);
    handle_ = nullptr;
  }
}

void PcapEventPublisher::configure() {
  // Reset the subscription states.
  promiscuous_ = 0;
  aggregate_interface_ = "";
  std::vector<std::string> filters;

  for (const auto& sub : subscriptions_) {
    auto sc = getSubscriptionContext(sub->context);
    if (aggregate_interface_ == "" || aggregate_interface_ == "default") {
      aggregate_interface_ = sc->interface;
    } else if (aggregate_interface_ != sc->interface) {
      // TODO(reed): Cannot support multiple devices/threads.
      aggregate_interface_ = "any";
    }

    if (sc->promiscuous) {
      promiscuous_ = 1;
    }

    if (sc->filter != "") {
      filters.push_back("(" + sc->filter + ")");
    }

    // Request for MAX snap length.
    if (sc->length == 0) {
      // Note: BUFSIZ is a libpcap-defined size.
      length_ = BUFSIZ;
    } else {
      length_ = (sc->length > length_) ? sc->length : length_;
    }
  }

  if (aggregate_interface_ == "") {
    // If no interface was set, let pcap choose the default.
    aggregate_interface_ = "default";
  }

  aggregate_filter_ = boost::algorithm::join(filters, " OR ");
}

void PcapEventPublisher::callback(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet) {
  auto ec = createEventContext();
  ec->ethernet = (pcap::ethernet *)packet;
  if (header->len < PCAP_ETHER_HDR_LEN) {
    // Invalid ethernet header.
    return;
  }

  u_int size_ip;
  u_char transport_protocol;
  ec->network_protocol = ntohs(ec->ethernet->ether_type);
  if (ec->network_protocol == PCAP_ETHER_TYPE_IP) {
    if (header->len < PCAP_IP_MIN_HDR_LEN + PCAP_ETHER_HDR_LEN) {
      // Not enough bytes for an IP header.
      return;
    }

    ec->ip = (pcap::ip *)(packet + PCAP_ETHER_HDR_LEN);
    size_ip = PCAP_IP_HL(ec->ip->ip_vhl) * 4;
    if (size_ip < PCAP_IP_MIN_HDR_LEN) {
      // Invalid IP header size.
      return;
    }

    ec->transport_protocol = ec->ip->ip_protocol;
    ec->payload_length = ntohs(ec->ip->ip_len) - size_ip;
  } else if (ec->network_protocol == PCAP_ETHER_TYPE_IP6) {
    if (header->len < PCAP_IP6_HDR_LEN + PCAP_ETHER_HDR_LEN) {
      // Not enough bytes for an IPv6 header.
      return;
    }

    ec->ip6 = (pcap::ip6 *)(packet + PCAP_ETHER_HDR_LEN);
    size_ip = PCAP_IP6_HDR_LEN;
    ec->transport_protocol = ec->ip6->ip_protocol;
    ec->payload_length = ntohs(ec->ip6->ip_len) - size_ip;
  } else {
    // Only support IP/IPv6 network types.
    return;
  }

  ec->transport = (pcap::transport *)(packet + PCAP_ETHER_HDR_LEN + size_ip);
  ec->payload = (u_char *)ec->transport;
  if (ec->transport_protocol == PCAP_IP_PROTOCOL_TCP) {
    if (ec->payload_length < PCAP_TCP_MIN_HDR_LEN) {
      // Not enough bytes for a TCP header.
      return;
    }

    u_int size_tcp = PCAP_TH_OFF(&(ec->transport->tcp)) * 4;
    if (size_tcp < PCAP_TCP_MIN_HDR_LEN) {
      // Invalid TCP header size.
      return;
    }
    ec->payload = (u_char *)(packet + PCAP_ETHER_HDR_LEN + size_ip + size_tcp);
    ec->payload_length = ec->payload_length - size_tcp;
  } else if (ec->transport_protocol == PCAP_IP_PROTOCOL_UDP) {
    if (ec->payload_length < PCAP_TCP_MIN_HDR_LEN) {
      // Not enough bytes for a UDP header.
      return;
    }
    ec->payload =
        (u_char *)(packet + PCAP_ETHER_HDR_LEN + size_ip + PCAP_UDP_HDR_LEN);
    ec->payload_length = ec->payload_length - PCAP_UDP_HDR_LEN;
  } else {
    // Unsupported transport protocol.
    return;
  }

  if (header->len > header->caplen) {
    // The capture didn't catch all bytes.
    ec->payload_length = ec->payload_length - (header->len - header->caplen);
  }

  // Must have the raw packet data in the event context.
  ec->header = header;
  ec->packet = packet;
  EventFactory::fire<PcapEventPublisher>(ec);
}

Status PcapEventPublisher::run() {
  if (aggregate_interface_ == "") {
    return Status(1, "No interfaces configured.");
  }

  char error[PCAP_ERRBUF_SIZE];
  std::string interface = "";
  if (aggregate_interface_ == "default") {
    char *device = pcap_lookupdev(nullptr);
    if (device == nullptr) {
      return Status(1, "Could not look up a requested 'default' interface.");
    } else {
      interface = std::string(device);
    }
  } else {
    interface = aggregate_interface_;
  }

  // Get interface properties.
  bpf_u_int32 self_address;
  bpf_u_int32 self_netmask;
  if (pcap_lookupnet(interface.c_str(), &self_netmask, &self_address, error) ==
      -1) {
    return Status(1, "Could not lookup pcap address/netmask.");
  }

  handle_ = pcap_open_live(
      interface.c_str(), length_, promiscuous_, kPcapPublisherTimeout, error);
  if (handle_ == nullptr) {
    return Status(1, "Could not open libpcap handle.");
  }

  struct bpf_program filter;
  if (pcap_compile(
          handle_, &filter, aggregate_filter_.c_str(), 0, self_address) == -1) {
    return Status(1, "Could not compile BPF filter.");
  }

  if (pcap_setfilter(handle_, &filter) == -1) {
    return Status(1, "Could not install BPF filter.");
  }

  // Start the packet loop, this will restart after the set timeout.
  while (true) {
    int status = pcap_loop(handle_, 0, &PcapEventPublisher::callback, nullptr);
    if (status == -1) {
      return Status(1, "Error looping on packet capture.");
    }
  }

  return Status(0, "Continue");
}

bool PcapEventPublisher::shouldFire(const PcapSubscriptionContextRef& sc,
                                    const PcapEventContextRef& ec) {
  // TODO(reed): Recompile the filter and check if the packet matches.
  return true;
}
}
