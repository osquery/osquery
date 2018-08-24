/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#include <osquery/ev2/event.h>

namespace osquery {
namespace ev2 {

Event::Event(EventId _id, EventTime _time)
  : id(_id)
  , time(_time)
{
}

} // namespace ev2
} // namespace osquery
