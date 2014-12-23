/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/tables.h>
#include "osquery/events/x/pcap.h"

namespace osquery {
namespace tables {

struct dns {
  u_short id;
  u_short flags;
  u_short questions;
  u_short answers;
  u_short authorities;
  u_short additional;
};

struct dns_record {
  u_short type;
  u_short resource_class;
  u_int ttl;
  u_int length;
  const u_char *data;
};

struct dns_query {
  u_short type;
  u_short resource_class;
};

std::map<u_short, std::string> kDNSQueryTypes = {
    {1, "A"},
    {2, "NS"},
    {5, "CNAME"},
    {6, "SOA"},
    {12, "PTR"},
    {15, "MX"},
    {16, "TXT"},
    {28, "AAAA"},
    {33, "SRV"},
    {49, "DHCID"},
    {251, "IXFR"},
    {252, "AXFR"},
    {255, "ALL"},
    {24, "SIG"},
    {25, "KEY"},
    {37, "CERT"},
    {43, "DS"},
    {44, "SSHFP"},
    {45, "IPSECKEY"},
    {46, "RRSIG"},
    {47, "NSEC"},
    {48, "DNSKEY"},
    {50, "NSEC3"},
    {52, "TLSA"},
    {60, "CDNSKEY"},
    {99, "SPF"},
    {249, "TKEY"},
    {250, "TSIG"},
    {257, "CAA"},
    {32768, "TA"},
    {32769, "DLV"},
};

/**
 * @brief Track time, action changes to /etc/passwd
 *
 * This is mostly an example EventSubscriber implementation.
 */
class DnsQueriesEventSubscriber : public EventSubscriber<PcapEventPublisher> {
  DECLARE_SUBSCRIBER("DnsQueriesEventSubscriber");

 public:
  void init();

  Status Callback(const PcapEventContextRef& ec);
};

REGISTER_EVENTSUBSCRIBER(DnsQueriesEventSubscriber);

void DnsQueriesEventSubscriber::init() {
  auto sc = createSubscriptionContext();
  sc->interface = "default";
  sc->filter = "udp port 53";
  // Support longer DNS queries.
  sc->length = 200;

  subscribe(&DnsQueriesEventSubscriber::Callback, sc);
}

Status DnsQueriesEventSubscriber::Callback(const PcapEventContextRef& ec) {
  if (ec->transport_protocol != PCAP_IP_PROTOCOL_UDP) {
    // Only support UDP DNS queries.
    return Status(1, "Not DNS");
  }

  if (ec->payload_length < (12 + 1)) {
    // Not enough data for a DNS header.
    // Note: need the size of the header + 1 for the first query byte = size.
    return Status(1, "Invalid DNS header.");
  }

  struct dns *dns = (struct dns *)ec->payload;
  const u_char *dns_data = (u_char *)(ec->payload + 12);

  if (ntohs(dns->questions) != 1) {
    // Not sure how to handle a DNS header with multiple queries.
    return Status(1, "Invalid DNS header.");
  }

  if (ntohs(dns->answers) != 0 || ntohs(dns->authorities) != 0 ||
      ntohs(dns->additional) != 0) {
    // Do not parse responses, just questions.
    return Status(1, "Not applicable.");
  }

  Row r;
  size_t word_size = (size_t)(dns_data[0]);
  u_short query_length = word_size + 1;
  for (size_t i = 1; i < ec->payload_length - (12 - 1); ++i) {
    if (dns_data[i] == 0) {
      break;
    }

    // Count number of characters until 0.
    if (word_size > 0) {
      if (dns_data[i] >= 32 && dns_data[i] <= 126) {
        r["query"] += (char)(dns_data[i]);
      }
      word_size--;
    } else {
      r["query"] += '.';
      word_size = (size_t)(dns_data[i]);

      query_length += word_size + 1;
    }
  }

  if (ec->payload_length < (query_length + 12 + 2 + 2)) {
    // Not enough data for type, class.
    return Status(1, "Invalid DNS Query.");
  }

  // The type/class portion of the query are both shorts.
  struct dns_query *query = (struct dns_query *)(dns_data + query_length + 1);

  r["transaction_id"] = INTEGER(ntohs(dns->id));
  r["flags"] = INTEGER(ntohs(dns->flags));

  auto type = ntohs(query->type);
  if (kDNSQueryTypes.count(type) == 0) {
    r["type"] = INTEGER(type);
  } else {
    r["type"] = kDNSQueryTypes[type];
  }

  auto resource_class = ntohs(query->resource_class);
  if (resource_class == 1) {
    r["class"] = "IN";
  } else {
    r["class"] = INTEGER(resource_class);
  }

  r["time"] = INTEGER(ec->time);
  add(r, ec->time);
  return Status(0, "OK");
}
}
}
