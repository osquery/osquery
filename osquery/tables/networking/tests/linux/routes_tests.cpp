/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <sys/socket.h>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

void genNetlinkRoutes(const struct nlmsghdr* netlink_msg, QueryData& results);

namespace {

// Appends an rtattr (header + payload) to the message body, optionally
// padding the body to the rtattr alignment so a following attribute starts
// correctly. A final attribute is appended unpadded so a truncated payload
// really ends the buffer.
void appendAttr(std::vector<char>& body,
                int type,
                const std::vector<char>& payload,
                bool pad) {
  struct rtattr attr;
  attr.rta_len = RTA_LENGTH(payload.size());
  attr.rta_type = type;
  const auto* attr_bytes = reinterpret_cast<const char*>(&attr);
  body.insert(body.end(), attr_bytes, attr_bytes + sizeof(attr));
  body.insert(body.end(), payload.begin(), payload.end());
  if (pad) {
    while (body.size() % RTA_ALIGNTO != 0) {
      body.push_back('\0');
    }
  }
}

// Builds an RTM_NEWROUTE message out of the given attributes; the last
// attribute is never padded.
std::vector<char> makeRouteMessage(
    int family, const std::vector<std::pair<int, std::vector<char>>>& attrs) {
  std::vector<char> body;
  for (size_t i = 0; i < attrs.size(); i++) {
    appendAttr(body, attrs[i].first, attrs[i].second, i + 1 < attrs.size());
  }

  struct rtmsg message;
  memset(&message, 0, sizeof(message));
  message.rtm_family = family;
  message.rtm_dst_len = 32;
  message.rtm_table = RT_TABLE_MAIN;
  message.rtm_protocol = RTPROT_STATIC;
  message.rtm_scope = RT_SCOPE_UNIVERSE;
  message.rtm_type = RTN_UNICAST;

  std::vector<char> buffer(NLMSG_HDRLEN + sizeof(message) + body.size(), '\0');
  struct nlmsghdr header;
  memset(&header, 0, sizeof(header));
  header.nlmsg_len = static_cast<__u32>(buffer.size());
  header.nlmsg_type = RTM_NEWROUTE;
  header.nlmsg_flags = NLM_F_REQUEST;
  memcpy(buffer.data(), &header, sizeof(header));
  memcpy(buffer.data() + NLMSG_HDRLEN, &message, sizeof(message));
  memcpy(
      buffer.data() + NLMSG_HDRLEN + sizeof(message), body.data(), body.size());
  return buffer;
}

std::vector<char> bytes(std::initializer_list<unsigned char> init) {
  return std::vector<char>(init.begin(), init.end());
}

} // namespace

class RoutesNetlinkTests : public testing::Test {};

// A truncated RTA_DST at the end of the message passes RTA_OK() with a
// two-byte payload; the destination read must not run past the message.
TEST_F(RoutesNetlinkTests, truncated_destination_payload) {
  auto buffer = makeRouteMessage(AF_INET, {{RTA_DST, bytes({0x64, 0x00})}});
  ASSERT_EQ(buffer.size(), 34U);
  QueryData results;
  genNetlinkRoutes(reinterpret_cast<const struct nlmsghdr*>(buffer.data()),
                   results);
  ASSERT_EQ(results.size(), 1U);
  // The address read is skipped, so the default-route fallback applies.
  EXPECT_EQ(results[0].at("destination"), "0.0.0.0");
}

// Same for the interface-index attribute: a two-byte payload must not be
// dereferenced as int.
TEST_F(RoutesNetlinkTests, truncated_oif_payload) {
  auto buffer = makeRouteMessage(AF_INET, {{RTA_OIF, bytes({0x01, 0x00})}});
  ASSERT_EQ(buffer.size(), 34U);
  QueryData results;
  genNetlinkRoutes(reinterpret_cast<const struct nlmsghdr*>(buffer.data()),
                   results);
  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].count("interface"), 0U);
}

// A well-formed route still parses: destination and metric come from the
// attributes, unchanged from the previous behavior.
TEST_F(RoutesNetlinkTests, wellformed_route) {
  auto buffer = makeRouteMessage(AF_INET,
                                 {
                                     {RTA_DST, bytes({10, 0, 0, 0})},
                                     {RTA_OIF, bytes({1, 0, 0, 0})},
                                     {RTA_PRIORITY, bytes({100, 0, 0, 0})},
                                 });
  ASSERT_EQ(buffer.size(), 52U);
  QueryData results;
  genNetlinkRoutes(reinterpret_cast<const struct nlmsghdr*>(buffer.data()),
                   results);
  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].at("destination"), "10.0.0.0");
  EXPECT_EQ(results[0].at("metric"), "100");
}

// The nested RTA_METRICS attributes get the same payload check; a truncated
// RTAX_MTU must not be dereferenced as int.
TEST_F(RoutesNetlinkTests, truncated_metrics_mtu) {
  std::vector<char> mtu_attr;
  struct rtattr inner;
  inner.rta_len = RTA_LENGTH(2);
  inner.rta_type = RTAX_MTU;
  const auto* inner_bytes = reinterpret_cast<const char*>(&inner);
  mtu_attr.insert(mtu_attr.end(), inner_bytes, inner_bytes + sizeof(inner));
  mtu_attr.push_back('\x01');
  mtu_attr.push_back('\x00');

  auto buffer = makeRouteMessage(AF_INET, {{RTA_METRICS, mtu_attr}});
  ASSERT_EQ(buffer.size(), 38U);
  QueryData results;
  genNetlinkRoutes(reinterpret_cast<const struct nlmsghdr*>(buffer.data()),
                   results);
  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].at("mtu"), "0");
}

} // namespace tables
} // namespace osquery
