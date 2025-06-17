/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>
#include <boost/noncopyable.hpp>

namespace osquery {

/**
 * @brief Manages OpenFrame authorization token
 * 
 * This class is responsible for storing and providing access to the OpenFrame
 * authorization token used for authentication with OpenFrame services.
 */
class OpenframeAuthorizationManager : private boost::noncopyable {
 public:
  /**
   * @brief Update the authorization token
   * 
   * @param token The new authorization token to store
   */
  void updateToken(const std::string& token);

  /**
   * @brief Get the current authorization token
   * 
   * @return The current authorization token
   */
  std::string getToken() const;

 private:
  OpenframeAuthorizationManager() = default;
  ~OpenframeAuthorizationManager() = default;

  std::string token_;

  friend class OpenframeAuthorizationManagerProvider;
};

} // namespace osquery 