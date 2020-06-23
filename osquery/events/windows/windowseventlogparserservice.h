/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <memory>

#include <boost/property_tree/ptree.hpp>

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

  static Status processEvent(boost::property_tree::ptree& event_object,
                             const std::wstring& xml_event);

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d_;
};
} // namespace osquery
