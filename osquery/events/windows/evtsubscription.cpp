/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <condition_variable>
#include <mutex>

#include <osquery/events/windows/evtsubscription.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
// Note: Windows ignores the exit code of this function
DWORD WINAPI EvtSubscriptionCallbackDispatcher(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE event) {
  auto& subscription = *static_cast<EvtSubscription*>(context);

  if (action == EvtSubscribeActionError) {
    LOG(ERROR)
        << "Windows event callback error 'EvtSubscribeActionError' for channel "
        << subscription.channel();

    return 0;

  } else if (action != EvtSubscribeActionDeliver) {
    LOG(ERROR) << "Windows event callback invoked with invalid action value "
                  "for channel "
               << subscription.channel();

    return 0;
  }

  subscription.processEvent(event);
  return 0U;
}

struct EvtSubscription::PrivateData final {
  EVT_HANDLE handle{nullptr};
  std::string channel;

  EventList event_list;
  std::mutex event_list_mutex;
  std::condition_variable event_list_cv;
};

Status EvtSubscription::create(EvtSubscription::Ref& obj,
                               const std::string& channel) {
  obj.reset();

  try {
    obj.reset(new EvtSubscription(channel));
    return Status::success();

  } catch (const std::bad_alloc&) {
    return Status::failure("Memory allocation failure");

  } catch (const Status& status) {
    return status;
  }
}

EvtSubscription::~EvtSubscription() {
  EvtClose(d_->handle);
}

const std::string EvtSubscription::channel() const {
  return d_->channel;
}

EvtSubscription::EventList EvtSubscription::getEvents() {
  EventList event_list;

  {
    std::unique_lock<std::mutex> lock(d_->event_list_mutex);

    auto ready = d_->event_list_cv.wait_for(
        lock, std::chrono::seconds(1U), [=]() -> bool {
          return !d_->event_list.empty();
        });

    if (ready) {
      event_list = std::move(d_->event_list);
      d_->event_list = {};
    }
  }

  return event_list;
}

EvtSubscription::EvtSubscription(const std::string& channel)
    : d_(new PrivateData) {
  d_->channel = channel;
  auto channel_utf16 = stringToWstring(channel);

  auto subscription = EvtSubscribe(nullptr,
                                   nullptr,
                                   channel_utf16.c_str(),
                                   L"*",
                                   nullptr,
                                   this,
                                   EvtSubscriptionCallbackDispatcher,
                                   EvtSubscribeToFutureEvents);

  if (subscription == nullptr) {
    auto error = GetLastError();
    throw Status::failure("Failed to subscribe to the channel named " +
                          channel + ". Error " + std::to_string(error));
  }

  d_->handle = subscription;
}

void EvtSubscription::processEvent(EVT_HANDLE event) {
  DWORD buffer_size{0U};
  DWORD property_count{0U};

  if (!EvtRender(nullptr,
                 event,
                 EvtRenderEventXml,
                 0U,
                 nullptr,
                 &buffer_size,
                 &property_count)) {
    auto error = GetLastError();

    if (error != ERROR_INSUFFICIENT_BUFFER) {
      LOG(ERROR) << "Failed to allocated the necessary memory to handle an "
                    "event for channel "
                 << d_->channel;

      return;
    }
  }

  std::wstring buffer(buffer_size / 2U, L'\0');
  if (!EvtRender(nullptr,
                 event,
                 EvtRenderEventXml,
                 buffer_size,
                 &buffer[0],
                 &buffer_size,
                 &property_count)) {
    auto error = GetLastError();

    LOG(ERROR) << "Failed to process an event for channel " << d_->channel
               << ". Error: " << error;

    return;
  }

  {
    std::lock_guard<std::mutex> lock(d_->event_list_mutex);
    d_->event_list.push_back(std::move(buffer));
  }

  d_->event_list_cv.notify_one();
}
} // namespace osquery
