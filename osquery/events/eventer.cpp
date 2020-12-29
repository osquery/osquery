
/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "eventer.h"

namespace osquery {

EventState Eventer::state() const {
  return state_;
}

void Eventer::state(EventState state) {
  state_ = state;
}

} // namespace osquery
