/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <ApplicationServices/ApplicationServices.h>
#include <CoreGraphics/CoreGraphics.h>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

const std::map<CGEventType, std::string> kEventMap = {
    {kCGEventNull, "EventNull"},
    {kCGEventLeftMouseDown, "LeftMouseDown"},
    {kCGEventLeftMouseUp, "EventLeftMouseUp"},
    {kCGEventRightMouseDown, "EventRightMouseDown"},
    {kCGEventRightMouseUp, "EventRightMouseUp"},
    {kCGEventMouseMoved, "EventMouseMoved"},
    {kCGEventLeftMouseDragged, "EventLeftMouseDragged"},
    {kCGEventKeyDown, "EventKeyDown"},
    {kCGEventKeyUp, "EventKeyUp"},
    {kCGEventFlagsChanged, "EventFlagsChanged"},
    {kCGEventScrollWheel, "EventScrollWheel"},
    {kCGEventTabletPointer, "EventTabletPointer"},
    {kCGEventTabletPointer, "EventTabletPointer"},
    {kCGEventOtherMouseDown, "EventOtherMouseDown"},
    {kCGEventOtherMouseUp, "EventOtherMouseUp"},
    {kCGEventOtherMouseDragged, "EventOtherMouseDragged"},
};

QueryData genEventTaps(QueryContext& context) {
  QueryData results;
  uint32_t tapCount = 0;
  @autoreleasepool {
    CGError err;
    err = CGGetEventTapList(0, nullptr, &tapCount);
    if (err != kCGErrorSuccess) {
      return results;
    }
    CGEventTapInformation* taps = static_cast<CGEventTapInformation*>(
        malloc(sizeof(CGEventTapInformation) * tapCount));
    if (taps == nullptr) {
      return results;
    }
    err = CGGetEventTapList(tapCount, taps, &tapCount);
    if (err != kCGErrorSuccess) {
      free(taps);
      return results;
    }
    for (size_t i = 0; i < tapCount; ++i) {
      for (const auto& type : kEventMap) {
        if ((taps[i].eventsOfInterest & CGEventMaskBit(type.first)) == 0) {
          continue;
        }
        Row r;
        r["enabled"] = INTEGER(taps[i].enabled);
        r["event_tap_id"] = INTEGER(taps[i].eventTapID);
        r["event_tapped"] = type.second;
        r["process_being_tapped"] = INTEGER(taps[i].processBeingTapped);
        r["tapping_process"] = INTEGER(taps[i].tappingProcess);
        results.push_back(r);
      }
    }
    free(taps);
  }
  return results;
}
}
}
