/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>

namespace osquery {
namespace events {

void dispatchSerializedEvent(const std::string& event);

} // namespace events
} // namespace osquery
