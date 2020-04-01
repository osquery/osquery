/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <pcap.h>

#include <osquery/events.h>
//#include <osquery/status.h>

namespace osquery {

/**
 * @brief Subscriptioning details for HTTPLookupEventPublisher events.
 *
 */
struct HTTPLookupSubscriptionContext : public SubscriptionContext {};

struct HTTPLookupEventContext : public EventContext {
    
  
  /// HTTP method used.
  std::string method;
    
  /// SSL/TLS protocol.
  std::string protocol;
    
  /// IP address of local interface.
  std::string local;

  /// IP address of HTTP responder.
  std::string remote;
    
  /// Source port.
  long s_port;
    
  /// Destination port.
  long d_port;

  /// HTTP request host. Ideally fully qualified host name.
  std::string host;

  /// HTTP host url port
  std::uint64_t host_port;

  /// HTTP uri comes along with host.
  std::string uri;
    
  /// Content type of the HTTP packet.
  std::string content_type;
  
  /// Http header user_agent.
  std::string user_agent;
    
  /// ja3 string for ja3 fingerprint calculation
  std::string ja3;
    
  /// ja3 fingerprint
  std::string ja3_fingerprint;
    
  /// Other http headers not included in columns .
  std::string other_headers;
};

using HTTPFilters = std::vector<std::pair<std::string, std::string>>;
using HTTPLookupEventContextRef = std::shared_ptr<HTTPLookupEventContext>;
using HTTPLookupSubscriptionContextRef =
    std::shared_ptr<HTTPLookupSubscriptionContext>;

/**
 * @brief Event publisher for DNS lookups intercepted via libpcap.
 */
class HTTPLookupEventPublisher
    : public EventPublisher<HTTPLookupSubscriptionContext,
                            HTTPLookupEventContext> {
  DECLARE_PUBLISHER("http_lookups");

 public:
  virtual ~HTTPLookupEventPublisher() {
    stop();
  }

  /// If DNS lookups are not enabled this returns non-zero status.
  Status setUp() override;

  /// Blocking call over pcap loop waiting for callbacks.
  Status run() override;

  /// Breaks pcap loop and free's resources.
  void stop() override;

 private:
  /// pcap handle.
  pcap_t* handle_{nullptr};

  /// BPF pseudo-assembly program structure.
  struct bpf_program fp_;

 private:
  /// Callback invoked by libpcap for matching packets.
  static void processPacket(unsigned char* args,
                            const struct pcap_pkthdr* header,
                            const unsigned char* packet);

  /// Helper function to create an EventContext.
  HTTPLookupEventContextRef createEventContextFrom(
      const uint32_t epochSecs,
      const std::string& method,
      const std::string& protocol,
      const std::string& local,
      const std::string& remote,
      long s_port,
      long d_port,
      const std::string& host,
      const std::uint64_t& host_port,
      const std::string& uri,
      const std::string& content_type,
      const std::string& user_agent,
      const std::string& ja3,
      const std::string& ja3_fingerprint,
      const std::string& other_headers);
  void getFilters(std::string& sFilters);

 private:
  HTTPFilters httpFilter_;
};
} // namespace osquery
