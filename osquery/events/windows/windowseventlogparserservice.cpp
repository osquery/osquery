/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <chrono>

#include <boost/property_tree/xml_parser.hpp>

#include <osquery/events/windows/windowseventlogparser.h>
#include <osquery/events/windows/windowseventlogpublisher.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/system.h>

namespace osquery {
namespace {
using ChannelQueue =
    std::unordered_map<std::string, EvtSubscription::EventList>;
}

struct WindowsEventLogParserService::PrivateData final {
  ChannelQueue channel_queue;
  std::mutex channel_queue_mutex;
  std::condition_variable channel_queue_cv;

  ChannelEventObjects channel_event_objects;
  std::mutex channel_event_objects_mutex;
  std::condition_variable channel_event_objects_cv;
};

WindowsEventLogParserService::WindowsEventLogParserService()
    : InternalRunnable("WindowsEventLogParserService"), d_(new PrivateData) {}

WindowsEventLogParserService::~WindowsEventLogParserService() {}

void WindowsEventLogParserService::start() {
  while (!interrupted()) {
    ChannelQueue channel_queue = {};

    {
      std::unique_lock<std::mutex> lock(d_->channel_queue_mutex);

      auto ready = d_->channel_queue_cv.wait_for(
          lock, std::chrono::seconds(1U), [=]() -> bool {
            return !d_->channel_queue.empty();
          });

      if (ready) {
        channel_queue = std::move(d_->channel_queue);
        d_->channel_queue = {};
      }
    }

    if (channel_queue.empty()) {
      continue;
    }

    ChannelEventObjects channel_event_objects = {};

    for (const auto& p : channel_queue) {
      const auto& channel = p.first;
      const auto& raw_event_list = p.second;

      auto channel_output_it = channel_event_objects.find(channel);
      if (channel_output_it == channel_event_objects.end()) {
        auto insert_status = channel_event_objects.insert({channel, {}});
        channel_output_it = insert_status.first;
      }

      auto& channel_output = channel_output_it->second;

      for (const auto& raw_event : raw_event_list) {
        boost::property_tree::ptree event_object;
        auto status = parseWindowsEventLogXML(event_object, raw_event);
        if (!status.ok()) {
          LOG(ERROR) << status.getMessage();
          continue;
        }

        channel_output.push_back(std::move(event_object));
      }
    }

    if (!channel_event_objects.empty()) {
      std::lock_guard<std::mutex> lock(d_->channel_event_objects_mutex);

      d_->channel_event_objects.insert(
          std::make_move_iterator(channel_event_objects.begin()),
          std::make_move_iterator(channel_event_objects.end()));
    }

    d_->channel_event_objects_cv.notify_one();
  }
}

void WindowsEventLogParserService::stop() {}

void WindowsEventLogParserService::addEventList(
    const std::string& channel, EvtSubscription::EventList event_list) {
  if (event_list.empty()) {
    return;
  }

  {
    std::lock_guard<std::mutex> lock(d_->channel_queue_mutex);

    auto channel_queue_it = d_->channel_queue.find(channel);
    if (channel_queue_it == d_->channel_queue.end()) {
      auto insert_status = d_->channel_queue.insert({channel, {}});
      channel_queue_it = insert_status.first;
    }

    auto& queue = channel_queue_it->second;

    queue.insert(queue.end(),
                 std::make_move_iterator(event_list.begin()),
                 std::make_move_iterator(event_list.end()));
  }

  d_->channel_queue_cv.notify_one();
}

WindowsEventLogParserService::ChannelEventObjects
WindowsEventLogParserService::getChannelEventObjects() {
  ChannelEventObjects output;

  {
    std::unique_lock<std::mutex> lock(d_->channel_event_objects_mutex);

    auto ready = d_->channel_event_objects_cv.wait_for(
        lock, std::chrono::milliseconds(200U), [=]() -> bool {
          return !d_->channel_event_objects.empty();
        });

    if (ready) {
      output = std::move(d_->channel_event_objects);
      d_->channel_event_objects = {};
    }
  }

  return output;
}

} // namespace osquery
