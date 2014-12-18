/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#include <boost/algorithm/string/join.hpp>

#include <glog/logging.h>

#include <osquery/events.h>
#include <osquery/filesystem.h>

#include "osquery/events/x/pcap.h"

namespace osquery {

REGISTER_EVENTPUBLISHER(PcapEventPublisher);

size_t kPcapPublisherDefaultLength = 100;
size_t kPcapPublisherTimeout = 60 * 1000;

PcapSubscriptionContext::PcapSubscriptionContext() {
  promiscuous = false;
  length = kPcapPublisherDefaultLength;
}

Status PcapEventPublisher::setUp() {
  // No need to setup anything, run will restart every time.
  return Status(0, "OK");
}

void PcapEventPublisher::tearDown() {
  if (handle_ != nullptr) {
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
      free(device);
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
  if (pcap_loop(handle_, 10, &PcapEventPublisher::callback, nullptr) == -1) {
    return Status(1, "Error looping on packet capture.");
  }

  return Status(0, "Continue");
}

bool PcapEventPublisher::shouldFire(const PcapSubscriptionContextRef& sc,
                                    const PcapEventContextRef& ec) {
  // TODO(reed): Recompile the filter and check if the packet matches.
  return true;
}
}
