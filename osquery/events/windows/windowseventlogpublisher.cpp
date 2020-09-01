/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/events/windows/windowseventlogpublisher.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

#include <plugins/config/parsers/feature_vectors.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace {
const int kCharFreqVectorLen{256};

Status loadCharacterFrequencyMap(std::vector<double>& character_frequency_map) {
  character_frequency_map = {};

  auto parser = Config::getParser(kFeatureVectorsRootKey);
  if (parser == nullptr) {
    return Status::failure(
        "Failed to acquire the feature_vectors configuration parser");
  }

  const auto& config = parser->getData().doc();
  if (!config.IsObject()) {
    return Status::failure("The configuration is not valid");
  }

  if (!config.HasMember("feature_vectors")) {
    return Status::success();
  }

  if (!config["feature_vectors"].IsObject()) {
    return Status::failure(
        "The configuration is not valid: feature_vectors is not an object");
  }

  if (!config["feature_vectors"].HasMember("character_frequencies")) {
    return Status::success();
  }

  if (!config["feature_vectors"]["character_frequencies"].IsArray()) {
    return Status::failure(
        "The character_frequencies configuration entity is not a valid array");
  }

  const auto& character_frequencies_array =
      config["feature_vectors"]["character_frequencies"];

  if (character_frequencies_array.Empty()) {
    return Status::failure(
        "The character_frequencies configuration entity array is empty");
  }

  if (character_frequencies_array.Size() > kCharFreqVectorLen) {
    return Status::failure(
        "The character_frequencies configuration entity array is too large");
  }

  std::vector<double> output(kCharFreqVectorLen, 0.0);
  for (rapidjson::SizeType i = 0; i < character_frequencies_array.Size(); i++) {
    if (character_frequencies_array[i].IsDouble()) {
      output[i] = character_frequencies_array[i].GetDouble();

    } else {
      return Status::failure(
          "The character_frequencies configuration entity array is not valid. "
          "Entry #" +
          std::to_string(i) + " is not a double");
    }
  }

  character_frequency_map = std::move(output);
  return Status::success();
}
} // namespace

FLAG(bool,
     enable_windows_events_publisher,
     false,
     "Enables the Windows events publisher");

REGISTER(WindowsEventLogPublisher,
         "event_publisher",
         "WindowsEventLogPublisher");

struct WindowsEventLogPublisher::PrivateData final {
  std::vector<EvtSubscription::Ref> subscription_list;
  std::shared_ptr<WindowsEventLogParserService> parser_service;
};

WindowsEventLogPublisher::WindowsEventLogPublisher() : d_(new PrivateData) {}

WindowsEventLogPublisher::~WindowsEventLogPublisher() {}

void WindowsEventLogPublisher::configure() {
  if (!FLAGS_enable_windows_events_publisher) {
    return;
  }

  tearDown();

  std::vector<double> character_frequency_map;
  auto status = loadCharacterFrequencyMap(character_frequency_map);
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
  }

  for (auto& current_subscriber : subscriptions_) {
    auto sc = getSubscriptionContext(current_subscriber->context);
    sc->character_frequency_map = character_frequency_map;

    const auto& channel_list = sc->channel_list;
    for (const auto& channel : channel_list) {
      EvtSubscription::Ref subscription = {};

      status = EvtSubscription::create(subscription, channel);
      if (!status.ok()) {
        auto error = GetLastError();
        LOG(WARNING) << "Failed to subscribe to " << channel << ": " << error;

      } else {
        d_->subscription_list.push_back(std::move(subscription));
      }
    }
  }
}

Status WindowsEventLogPublisher::run() {
  if (!FLAGS_enable_windows_events_publisher) {
    return Status::failure("Publisher disabled by configuration");
  }

  d_->parser_service = std::make_shared<WindowsEventLogParserService>();
  Dispatcher::addService(d_->parser_service);

  WindowsEventLogParserService::ChannelEventObjects channel_event_objects;
  auto last_fired_event_time = std::chrono::steady_clock::now();

  while (!isEnding()) {
    EvtSubscription::EventList event_list;

    for (auto& subscription : d_->subscription_list) {
      auto event_list = subscription->getEvents();

      if (!event_list.empty()) {
        d_->parser_service->addEventList(subscription->channel(), event_list);
      }
    }

    // Buffer the events so we can take advantage of write batching
    auto new_events = d_->parser_service->getChannelEventObjects();
    if (channel_event_objects.empty()) {
      channel_event_objects = std::move(new_events);

    } else {
      for (auto& p : new_events) {
        const auto& channel_name = p.first;
        auto& event_list = p.second;

        if (channel_event_objects.count(channel_name) == 0) {
          channel_event_objects[channel_name] = std::move(event_list);

        } else {
          auto& buffer = channel_event_objects[channel_name];
          buffer.insert(buffer.end(),
                        std::make_move_iterator(event_list.begin()),
                        std::make_move_iterator(event_list.end()));
        }
      }
    }

    new_events = {};

    auto current_time = std::chrono::steady_clock::now();
    if (current_time - last_fired_event_time >= std::chrono::seconds(2U)) {
      for (auto& p : channel_event_objects) {
        const auto& channel_name = p.first;
        auto& event_objects = p.second;

        auto event_context = createEventContext();
        event_context->channel = channel_name;
        event_context->event_objects = std::move(event_objects);

        fire(event_context);
      }

      channel_event_objects = {};

      last_fired_event_time = std::chrono::steady_clock::now();
    }
  }

  return Status::success();
}

double WindowsEventLogPublisher::cosineSimilarity(
    const std::string& buffer, const std::vector<double>& global_freqs) {
  std::vector<double> buffer_freqs(kCharFreqVectorLen, 0.0);

  auto buffer_size = buffer.size();
  for (auto chr : buffer) {
    if (chr < kCharFreqVectorLen) {
      buffer_freqs[chr] += 1.0 / buffer_size;
    }
  }

  auto dot = 0.0;
  auto mag1 = 0.0;
  auto mag2 = 0.0;

  for (size_t i = 0; i < global_freqs.size(); i++) {
    dot += buffer_freqs[i] * global_freqs[i];
    mag1 += buffer_freqs[i] * buffer_freqs[i];
    mag2 += global_freqs[i] * global_freqs[i];
  }

  mag1 = std::sqrt(mag1);
  mag2 = std::sqrt(mag2);

  return dot / (mag1 * mag2);
}

void WindowsEventLogPublisher::tearDown() {
  if (!FLAGS_enable_windows_events_publisher) {
    return;
  }

  d_->subscription_list.clear();
}

bool WindowsEventLogPublisher::shouldFire(const SCRef& subscription,
                                          const ECRef& event) const {
  auto lowercase_channel = event->channel;
  std::transform(lowercase_channel.begin(),
                 lowercase_channel.end(),
                 lowercase_channel.begin(),
                 ::tolower);

  return (subscription->channel_list.count(lowercase_channel) > 0U);
}
} // namespace osquery
