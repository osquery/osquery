/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <ApplicationServices/ApplicationServices.h>
#include <CoreGraphics/CoreGraphics.h>

#include <osquery/system.h>
#include <osquery/tables.h>

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
