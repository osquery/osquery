/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#define _WIN32_DCOM

#include <Windows.h>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/tokenizer.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/core/windows/wmi.h"
#include "osquery/events/windows/windows_event_log.h"

namespace pt = boost::property_tree;

namespace osquery {

REGISTER(WindowsEventLogEventPublisher, "event_publisher", "windows_events");

const std::chrono::milliseconds kWinEventLogPause(200);

void WindowsEventLogEventPublisher::configure() {
  stop();
  for (auto& sub : subscriptions_) {
    auto sc = getSubscriptionContext(sub->context);
    for (const auto& chan : sc->sources) {
      /*
       * We don't apply any filtering to the Windows event logs. It's assumed
       * that if filtering is required, this will be handled via SQL queries
       * or in the subscriber logic.
       */
      auto hSubscription =
          EvtSubscribe(nullptr,
                       nullptr,
                       chan.c_str(),
                       L"*",
                       nullptr,
                       nullptr,
                       EVT_SUBSCRIBE_CALLBACK(winEventCallback),
                       EvtSubscribeToFutureEvents);
      if (hSubscription == nullptr) {
        LOG(WARNING) << "Failed to subscribe to "
                     << wstringToString(chan.c_str()) << ": " << GetLastError();
      } else {
        win_event_handles_.push_back(hSubscription);
      }
    }
  }
}

Status WindowsEventLogEventPublisher::run() {
  pauseMilli(100);
  return Status(0, "OK");
}

void WindowsEventLogEventPublisher::stop() {
  for (auto& e : win_event_handles_) {
    if (e != nullptr) {
      EvtClose(e);
    }
  }
  win_event_handles_.clear();
}

void WindowsEventLogEventPublisher::tearDown() {
  stop();
}

unsigned long __stdcall WindowsEventLogEventPublisher::winEventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
  UNREFERENCED_PARAMETER(pContext);

  switch (action) {
  case EvtSubscribeActionError:
    VLOG(1) << "Windows event callback failed: " << hEvent;
    break;
  case EvtSubscribeActionDeliver: {
    pt::ptree propTree;
    auto s = parseEvent(hEvent, propTree);
    if (s.ok()) {
      auto ec = createEventContext();
      /// We leave the parsing of the properties up to the subscriber
      ec->eventRecord = propTree;
      ec->channel = stringToWstring(propTree.get("Event.System.Channel", ""));
      EventFactory::fire<WindowsEventLogEventPublisher>(ec);
    } else {
      VLOG(1) << "Error rendering Windows event log: " << s.getCode();
    }
  } break;

  default:
    VLOG(1) << "Received unknown action from Windows event log: "
            << GetLastError();
  }
  return ERROR_SUCCESS;
}

Status WindowsEventLogEventPublisher::parseEvent(EVT_HANDLE evt,
                                                 pt::ptree& propTree) {
  DWORD buffSize = 0;
  DWORD buffUsed = 0;
  DWORD propCount = 0;
  LPWSTR xml = nullptr;
  Status status;

  if (!EvtRender(nullptr,
                 evt,
                 EvtRenderEventXml,
                 buffSize,
                 xml,
                 &buffUsed,
                 &propCount)) {
    if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
      buffSize = buffUsed;
      xml = static_cast<LPWSTR>(malloc(buffSize));
      if (xml != nullptr) {
        EvtRender(nullptr,
                  evt,
                  EvtRenderEventXml,
                  buffSize,
                  xml,
                  &buffUsed,
                  &propCount);
      } else {
        status = Status(1, "Unable to reserve memory for event log buffer");
      }
    }
  }

  if (ERROR_SUCCESS == GetLastError()) {
    std::stringstream ss;
    ss << wstringToString(xml);
    read_xml(ss, propTree);
  } else {
    status = Status(GetLastError(), "Event rendering failed");
  }

  if (xml != nullptr) {
    free(xml);
  }

  return status;
}

bool WindowsEventLogEventPublisher::shouldFire(
    const WindowsEventLogSubscriptionContextRef& sc,
    const WindowsEventLogEventContextRef& ec) const {
  return sc->sources.find(ec->channel) != sc->sources.end();
}

bool WindowsEventLogEventPublisher::isSubscriptionActive() const {
  return win_event_handles_.size() > 0;
}
}
