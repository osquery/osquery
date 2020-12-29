/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <memory>
#include <unordered_set>

#include <osquery/events/eventpublisher.h>
#include <osquery/events/windows/windowseventlogparserservice.h>

namespace osquery {
struct WindowsEventLogSubscriptionContext : public SubscriptionContext {
  std::unordered_set<std::string> channel_list;
  std::vector<double> character_frequency_map;

 private:
  friend class WindowsEventLogPublisher;
};

struct WindowsEventLogEC : public EventContext {
  std::string channel;
  WindowsEventLogParserService::PropertyTreeList event_objects;
};

using WindowsEventLogECRef = std::shared_ptr<WindowsEventLogEC>;

using WindowsEventLogSCRef =
    std::shared_ptr<WindowsEventLogSubscriptionContext>;

class WindowsEventLogPublisher
    : public EventPublisher<WindowsEventLogSubscriptionContext,
                            WindowsEventLogEC> {
 public:
  WindowsEventLogPublisher();
  virtual ~WindowsEventLogPublisher() override;

  bool shouldFire(const SCRef& subscription, const ECRef& event) const override;
  void configure() override;
  void tearDown() override;
  Status run() override;

  static double cosineSimilarity(const std::string& buffer,
                                 const std::vector<double>& global_freqs);

 private:
  DECLARE_PUBLISHER("WindowsEventLogPublisher");

  struct PrivateData;
  std::unique_ptr<PrivateData> d_;

 public:
  friend class WindowsEventLogTests;
  FRIEND_TEST(WindowsEventLogTests, test_register_event_pub);
};
} // namespace osquery
