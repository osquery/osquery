/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "openframe_authorization_manager.h"

namespace osquery {

void OpenframeAuthorizationManager::updateToken(const std::string& token) {
  token_ = token;
}

std::string OpenframeAuthorizationManager::getToken() const {
  return token_;
}

} // namespace osquery 