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

#include <boost/property_tree/ptree.hpp>

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/events/windows/evtsubscription.h>
#include <osquery/utils/system/system.h>

namespace osquery {
class WindowsEventLogParserService final : public InternalRunnable {
 public:
  using PropertyTreeList = std::vector<boost::property_tree::ptree>;
  using ChannelEventObjects = std::unordered_map<std::string, PropertyTreeList>;

  WindowsEventLogParserService();
  virtual ~WindowsEventLogParserService() override;

  virtual void start() override;
  virtual void stop() override;

  void addEventList(const std::string& channel,
                    EvtSubscription::EventList event_list);

  ChannelEventObjects getChannelEventObjects();

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d_;
};
} // namespace osquery
