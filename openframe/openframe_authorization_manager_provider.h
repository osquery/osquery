/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <boost/noncopyable.hpp>
#include "openframe_authorization_manager.h"

namespace osquery {

/**
 * @brief Provider class for OpenFrame authorization manager
 * 
 * This class provides a single point of access to the OpenFrame authorization
 * manager singleton instance. It ensures thread-safe access to the manager.
 */
class OpenframeAuthorizationManagerProvider : private boost::noncopyable {
 public:
  /**
   * @brief Get the singleton instance of OpenframeAuthorizationManager
   * 
   * @return Reference to the singleton instance
   */
  static OpenframeAuthorizationManager& getInstance() {
    static OpenframeAuthorizationManager instance;
    return instance;
  }

 private:
  OpenframeAuthorizationManagerProvider() = default;
  ~OpenframeAuthorizationManagerProvider() = default;
};

} // namespace osquery 