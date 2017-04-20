/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <ApplicationServices/ApplicationServices.h>
#include <CoreGraphics/CoreGraphics.h>
#include <osquery/system.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {
const std::map <CGEventMask, std::string> kEventMap =
{
  {CGEventMaskBit(kCGEventNull), "EventNull"},
  {CGEventMaskBit(kCGEventLeftMouseDown), "LeftMouseDown"},
  {CGEventMaskBit(kCGEventLeftMouseUp), "EventLeftMouseUp"},
  {CGEventMaskBit(kCGEventRightMouseDown), "EventRightMouseDown"},
  {CGEventMaskBit(kCGEventRightMouseUp), "EventRightMouseUp"},
  {CGEventMaskBit(kCGEventMouseMoved), "EventMouseMoved"},
  {CGEventMaskBit(kCGEventLeftMouseDragged), "EventLeftMouseDragged"},
  {CGEventMaskBit(kCGEventKeyDown), "EventKeyDown"},
  {CGEventMaskBit(kCGEventKeyUp), "EventKeyUp"},
  {CGEventMaskBit(kCGEventFlagsChanged), "EventFlagsChanged"},
  {CGEventMaskBit(kCGEventScrollWheel), "EventScrollWheel"},
  {CGEventMaskBit(kCGEventTabletPointer), "EventTabletPointer"},
  {CGEventMaskBit(kCGEventTabletPointer), "EventTabletPointer"},
  {CGEventMaskBit(kCGEventOtherMouseDown), "EventOtherMouseDown"},
  {CGEventMaskBit(kCGEventOtherMouseUp), "EventOtherMouseUp"},
  {CGEventMaskBit(kCGEventOtherMouseDragged), "EventOtherMouseDragged"},
};

  QueryData genEventTaps(QueryContext & context) {
    QueryData results;
    uint32_t tapCount = 0;
    CGError err;
    err = CGGetEventTapList(NULL, NULL, & tapCount);
    if(err != 0) {
      return results;
    }
    CGEventTapInformation taps[tapCount];
    err = CGGetEventTapList(tapCount, taps, & tapCount);
    if(err != 0) {
      return results;
    }
    for (size_t i = 0; i < tapCount; ++i) {
      for (const auto & type: kEventMap) {
        if ((taps[i].eventsOfInterest & type.first) == 0) {
          continue;
        }
        Row r;
        r["enabled"] = std::to_string(taps[i].enabled);
        r["event_tap_id"] = std::to_string(taps[i].eventTapID);
        r["event_tapped"] = type.second;
        r["process_being_tapped"] = std::to_string(taps[i].processBeingTapped);
        r["tapping_process"] = std::to_string(taps[i].tappingProcess);
        results.push_back(r);
      }
    }
    return results;
  }

 }
}
